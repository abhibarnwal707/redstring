"""Build evals/gold/questions.jsonl: run every question's Cypher against the graph and store the
result as the gold answer. Gold answers are never typed by hand.

Usage: uv run python -m redstring_cti.gold.build        (or `make gold`)
"""

import argparse
import json
import logging
import random
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from neo4j import Driver

from redstring_cti.gold.models import (
    BUILD_INFO_PATH,
    GOLD_PATH,
    AnswerStyle,
    GoldQuestion,
    QuestionType,
)
from redstring_cti.gold.spec import SPECS, QuestionSpec
from redstring_cti.graph.loader import get_driver, graph_counts

log = logging.getLogger(__name__)

SPLIT_SEED = 42
# Held-out test questions: 30 in total, stratified by type, and for multi-hop by hop count and for
# aggregation by answer style, so the headline numbers include the hard cases.
TEST_QUOTAS: dict[tuple[str, str], int] = {
    ("single_hop", ""): 8,
    ("multi_hop", "2"): 7,
    ("multi_hop", "3"): 3,
    ("multi_hop", "4"): 2,
    ("aggregation", "ranked_list"): 3,
    ("aggregation", "count"): 2,
    ("semantic", ""): 3,
    ("unanswerable", ""): 2,
}
MIN_AI_IN_TEST = 2
EXPECTED_PER_TYPE: dict[QuestionType, int] = {
    "single_hop": 40,
    "multi_hop": 60,
    "aggregation": 25,
    "semantic": 15,
    "unanswerable": 10,
}


@dataclass
class Result:
    ids: list[str]
    values: list[str]
    cypher: str


def run(driver: Driver, cypher: str) -> list[dict[str, Any]]:
    with driver.session() as session:
        return [dict(r) for r in session.run(cypher)]


def evaluate(driver: Driver, spec: QuestionSpec) -> Result:
    style: AnswerStyle = spec.style
    cypher = spec.cypher
    if style == "ranked_list":
        assert spec.ranked_n, f"ranked_list needs ranked_n: {spec.question}"
        probe = run(driver, cypher.format(limit=spec.ranked_n + 1))
        if len(probe) > spec.ranked_n and probe[spec.ranked_n - 1]["value"] == probe[spec.ranked_n]["value"]:
            raise ValueError(f"tie at the top-{spec.ranked_n} boundary: {spec.question}")
        cypher = cypher.format(limit=spec.ranked_n)
    rows = run(driver, cypher)
    if style in ("list", "ranked_list"):
        return Result([str(r["id"]) for r in rows], [], cypher)
    if style == "count":
        if len(rows) != 1:
            raise ValueError(f"count query must return one row ({len(rows)}): {spec.question}")
        return Result([], [str(rows[0]["value"])], cypher)
    if rows:
        raise ValueError(f"unanswerable question has an answer in the graph: {spec.question} -> {rows[:3]}")
    if spec.precondition and not run(driver, spec.precondition):
        raise ValueError(f"precondition returned nothing (entity missing?): {spec.question}")
    return Result([], [], cypher)


def stratum(spec: QuestionSpec) -> tuple[str, str]:
    if spec.type == "multi_hop":
        return (spec.type, str(spec.hops))
    if spec.type == "aggregation":
        return (spec.type, spec.style)
    return (spec.type, "")


def assign_splits(specs: list[QuestionSpec]) -> dict[int, str]:
    """Seeded, stratified. At least MIN_AI_IN_TEST AI-technique questions are forced into the test set."""
    rng = random.Random(SPLIT_SEED)
    quotas = dict(TEST_QUOTAS)
    test: set[int] = set()
    ai_idx = [i for i, s in enumerate(specs) if "ai_technique" in s.tags and s.type != "unanswerable"]
    for i in rng.sample(ai_idx, MIN_AI_IN_TEST):
        test.add(i)
        quotas[stratum(specs[i])] -= 1
    for key, k in quotas.items():
        pool = [i for i, s in enumerate(specs) if stratum(s) == key and i not in test]
        test.update(rng.sample(pool, k))
    return {i: ("test" if i in test else "dev") for i in range(len(specs))}


def build(driver: Driver) -> list[GoldQuestion]:
    counts = Counter(s.type for s in SPECS)
    if dict(counts) != EXPECTED_PER_TYPE:
        raise ValueError(f"question mix {dict(counts)} != expected {EXPECTED_PER_TYPE}")
    questions_seen = [s.question for s in SPECS]
    if len(set(questions_seen)) != len(questions_seen):
        raise ValueError("duplicate question text")
    splits = assign_splits(SPECS)
    out: list[GoldQuestion] = []
    errors: list[str] = []
    for i, spec in enumerate(SPECS):
        try:
            res = evaluate(driver, spec)
        except ValueError as exc:
            errors.append(f"q{i + 1:03d}: {exc}")
            continue
        out.append(
            GoldQuestion(
                id=f"q{i + 1:03d}",
                question=spec.question,
                type=spec.type,
                hops=spec.hops,
                answer_style=spec.style,
                gold_ids=res.ids,
                gold_values=res.values,
                gold_cypher=" ".join(res.cypher.split()),
                precondition_cypher=" ".join(spec.precondition.split()) if spec.precondition else None,
                split=splits[i],  # type: ignore[arg-type]
                tags=sorted(spec.tags),
                notes=spec.notes,
            )
        )
    if errors:
        raise ValueError(f"{len(errors)} question(s) failed:\n  " + "\n  ".join(errors))
    return out


def build_info(driver: Driver, questions: list[GoldQuestion]) -> dict[str, Any]:
    versions = run(
        driver,
        """MATCH (n) WHERE n:Group OR n:CWE OR n:CAPEC
           RETURN head(labels(n)) AS label, collect(DISTINCT n.source_version) AS versions""",
    )
    return {
        "built_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "questions": len(questions),
        "by_type": dict(Counter(q.type for q in questions)),
        "by_split": dict(Counter(q.split for q in questions)),
        "graph": graph_counts(driver),
        "source_versions": {v["label"]: v["versions"] for v in versions},
        "split_seed": SPLIT_SEED,
        "note": "Gold answers are Cypher results over this graph snapshot. If the graph is rebuilt or updated, "
        "rerun `make gold` and review the diff; tests/test_gold.py fails when answers drift.",
    }


def write(questions: list[GoldQuestion], info: dict[str, Any], path: Path = GOLD_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(q.model_dump_json() + "\n" for q in questions))
    BUILD_INFO_PATH.write_text(json.dumps(info, indent=2) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the gold evaluation set from the live graph.")
    parser.add_argument("--dry-run", action="store_true", help="validate and print a summary; do not write files")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.ERROR)  # "property does not exist" warnings are intentional
    driver = get_driver()
    try:
        questions = build(driver)
        info = build_info(driver, questions)
    finally:
        driver.close()
    for q in questions:
        size = len(q.gold_ids) if q.gold_ids else (q.gold_values[0] if q.gold_values else "-")
        log.info("%s %-12s %-11s hops=%d %-5s gold=%s | %s", q.id, q.type, q.answer_style, q.hops, q.split, size, q.question[:70])
    log.info("by type %s, by split %s", info["by_type"], info["by_split"])
    if not args.dry_run:
        write(questions, info)
        log.info("wrote %s", GOLD_PATH)


if __name__ == "__main__":
    main()
