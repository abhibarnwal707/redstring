from collections import Counter
from typing import Any

import pytest
from neo4j import Driver
from pydantic import ValidationError

from redstring_cti.gold.build import EXPECTED_PER_TYPE, TEST_QUOTAS, stratum
from redstring_cti.gold.models import GOLD_PATH, ID_PATTERN, GoldQuestion, load_gold
from redstring_cti.gold.spec import SPECS

GOLD = load_gold() if GOLD_PATH.exists() else []
needs_gold = pytest.mark.skipif(not GOLD, reason="run `make gold` first")


def _valid(**over: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "q001", "question": "Which mitigations exist for T1566?", "type": "single_hop", "hops": 1,
        "answer_style": "list", "gold_ids": ["M1017"], "gold_values": [], "gold_cypher": "RETURN 1", "split": "dev",
    }
    return base | over


# ------------------------------------------------------------------ schema rules (no database needed)
def test_model_accepts_a_valid_question() -> None:
    assert GoldQuestion(**_valid()).gold_ids == ["M1017"]


@pytest.mark.parametrize(
    "bad",
    [
        {"gold_ids": []},  # list needs an answer
        {"gold_ids": ["M1017", "M1017"]},  # duplicates
        {"gold_ids": ["m1017"]},  # malformed id
        {"gold_ids": ["X1"]},
        {"id": "q1"},
        {"hops": 0},  # answerable needs hops
        {"answer_style": "count", "gold_ids": ["M1017"], "gold_values": ["3"]},  # count has no ids
        {"answer_style": "count", "gold_ids": [], "gold_values": []},  # count needs a value
        {"type": "unanswerable", "answer_style": "not_found", "hops": 0, "gold_ids": ["M1017"]},
        {"type": "unanswerable", "answer_style": "list", "hops": 0},  # unanswerable must be not_found
        {"answer_style": "not_found"},  # not_found only for unanswerable
    ],
)
def test_model_rejects_inconsistent_questions(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        GoldQuestion(**_valid(**bad))


def test_id_pattern_covers_every_entity_kind() -> None:
    for ok in ("T1566", "T1566.001", "G0016", "S0154", "M1017", "TA0001", "C0024", "CAPEC-163", "CWE-89", "CVE-2024-38112"):
        assert ID_PATTERN.match(ok), ok
    assert not ID_PATTERN.match("APT29")


# ------------------------------------------------------------------ shape of the committed set
@needs_gold
def test_mix_and_split_are_as_designed() -> None:
    assert len(GOLD) == 150
    assert dict(Counter(q.type for q in GOLD)) == EXPECTED_PER_TYPE
    assert Counter(q.split for q in GOLD) == {"dev": 120, "test": 30}
    assert [q.id for q in GOLD] == [f"q{i:03d}" for i in range(1, 151)]
    assert len({q.question for q in GOLD}) == 150


@needs_gold
def test_test_split_is_stratified_by_type_hops_and_style() -> None:
    by_stratum = Counter(
        stratum(next(s for s in SPECS if s.question == q.question)) for q in GOLD if q.split == "test"
    )
    assert dict(by_stratum) == TEST_QUOTAS


@needs_gold
def test_enough_ai_and_hard_questions() -> None:
    assert sum("ai_technique" in q.tags for q in GOLD) >= 10
    assert sum("ai_technique" in q.tags and q.split == "test" for q in GOLD) >= 2
    assert sum(q.hops >= 3 for q in GOLD if q.type == "multi_hop") >= 20
    assert sum(q.hops == 4 for q in GOLD) >= 5


@needs_gold
def test_committed_file_matches_the_spec() -> None:
    """Editing spec.py without rerunning `make gold` would leave the file stale."""
    assert len(SPECS) == len(GOLD)
    for spec, q in zip(SPECS, GOLD, strict=True):
        assert (spec.question, spec.type, spec.hops, spec.style) == (q.question, q.type, q.hops, q.answer_style)
        assert sorted(spec.tags) == q.tags


@needs_gold
def test_ranked_lists_have_the_requested_length() -> None:
    for q in GOLD:
        if q.answer_style == "ranked_list":
            assert f"LIMIT {len(q.gold_ids)}" in q.gold_cypher, q.id


# ------------------------------------------------------------------ gold answers still match the graph
@pytest.fixture(scope="module")
def graph_ready(driver: Driver) -> None:
    with driver.session() as session:
        n = session.run("MATCH (v:CVE {kev: true}) RETURN count(v) AS c").single()
    if not n or n["c"] == 0:
        pytest.skip("graph not loaded (make load)")


@needs_gold
@pytest.mark.parametrize("q", GOLD, ids=lambda q: q.id)
def test_gold_answer_still_matches_graph(driver: Driver, graph_ready: None, q: GoldQuestion) -> None:
    with driver.session() as session:
        rows = [dict(r) for r in session.run(q.gold_cypher)]
        pre = [dict(r) for r in session.run(q.precondition_cypher)] if q.precondition_cypher else None
    if q.answer_style == "list":
        assert {str(r["id"]) for r in rows} == set(q.gold_ids), q.question
    elif q.answer_style == "ranked_list":
        assert [str(r["id"]) for r in rows] == q.gold_ids, q.question  # order matters
    elif q.answer_style == "count":
        assert [str(r["value"]) for r in rows] == q.gold_values, q.question
    else:
        assert rows == [], f"now answerable from the graph: {q.question}"
        if q.precondition_cypher:
            assert pre, f"entity for unanswerable question vanished: {q.question}"
