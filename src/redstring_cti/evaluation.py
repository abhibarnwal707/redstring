"""Run a question-answering system over the gold set, score it, and write the result tables.

Runs are resumable: each answered question is appended to results.jsonl immediately, so an
interrupted run (or a rate-limit stall) continues where it stopped, and the LLM cache makes repeats free.
"""

import argparse
import csv
import json
import logging
import statistics
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from redstring_cti.config import LLM_CHAINS
from redstring_cti.gold.models import GoldQuestion, load_gold
from redstring_cti.llm import LLMError, record_name
from redstring_cti.retrieval.common import SystemAnswer
from redstring_cti.scoring import score_question

log = logging.getLogger(__name__)

RESULTS_DIR = Path(__file__).resolve().parents[2] / "evals" / "results"
RUNS_DIR = RESULTS_DIR / "runs"
SYSTEM_NAMES = ("vector_rag", "text2cypher")


# ------------------------------------------------------------------ choosing the model chain
def resolve_chain(text: str) -> tuple[str, tuple[str, ...]]:
    """'groq' | 'openrouter' | 'groq+openrouter' | 'spec1,spec2' -> (tag for the run name, model specs)."""
    if text in LLM_CHAINS:
        return text, LLM_CHAINS[text]
    specs = tuple(t.strip() for t in text.split(",") if t.strip())
    if not specs:
        raise SystemExit(f"empty --llm-chain; use one of {sorted(LLM_CHAINS)} or comma-separated model specs")
    return "custom", specs


# ------------------------------------------------------------------ selecting questions
def select_questions(
    gold: list[GoldQuestion],
    split: str,
    *,
    ids: list[str] | None = None,
    limit: int | None = None,
    exclude: set[str] | None = None,
) -> list[GoldQuestion]:
    chosen = [q for q in gold if q.split == split and q.id not in (exclude or set())]
    if ids:
        chosen = [q for q in chosen if q.id in set(ids)]
    return chosen[:limit] if limit else chosen


# ------------------------------------------------------------------ result store
class RunStore:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.path = directory / "results.jsonl"
        directory.mkdir(parents=True, exist_ok=True)

    def load(self, allowed_models: set[str] | None = None) -> dict[str, dict[str, Any]]:
        """Latest record per question. With `allowed_models`, records answered by any other model are
        ignored, so resuming under a stricter chain re-runs them instead of keeping a mixed result."""
        if not self.path.exists():
            return {}
        records = (json.loads(line) for line in self.path.read_text().splitlines() if line.strip())
        by_id = {r["id"]: r for r in records}
        if allowed_models is None:
            return by_id
        return {i: r for i, r in by_id.items() if set(r["models"]) <= allowed_models}

    def append(self, record: dict[str, Any]) -> None:
        with self.path.open("a") as f:
            f.write(json.dumps(record, default=str) + "\n")


def make_record(q: GoldQuestion, ans: SystemAnswer, system: str) -> dict[str, Any]:
    score = score_question(q, ans.text, set(ans.evidence_ids))
    return {
        "id": q.id, "system": system, "split": q.split, "type": q.type, "hops": q.hops, "style": q.answer_style,
        "question": q.question, "answer": ans.text, **score,
        "gold_ids": q.gold_ids, "gold_values": q.gold_values,
        "wall_s": round(ans.wall_s, 3), "service_s": round(ans.service_s, 3), "waited_s": round(ans.waited_s, 3), "llm_s": round(ans.llm_latency_s, 3),
        "prompt_tokens": ans.prompt_tokens, "completion_tokens": ans.completion_tokens,
        "cost_usd": ans.cost_usd, "models": ans.models, "llm_calls": len(ans.calls),
        "fell_back": any(c.fallback_from for c in ans.calls), "cached": all(c.cached for c in ans.calls) if ans.calls else False,
        "cypher": ans.cypher, "rows": ans.rows, "error": ans.error, "extra": ans.extra,
    }


# ------------------------------------------------------------------ aggregation
def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct / 100
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def group_key(r: dict[str, Any]) -> str:
    if r["type"] == "multi_hop":
        return f"multi_hop ({r['hops']}-hop)"
    if r["type"] == "aggregation":
        return f"aggregation ({'count' if r['style'] == 'count' else 'ranked'})"
    return str(r["type"])


def summarise(records: list[dict[str, Any]]) -> dict[str, Any]:
    def block(rs: list[dict[str, Any]]) -> dict[str, Any]:
        listy = [r for r in rs if r["style"] in ("list", "ranked_list")]
        answered = [r for r in rs if r["style"] != "not_found"]
        supported = [r for r in answered if r["cited"]]
        return {
            "n": len(rs),
            "accuracy": statistics.fmean(r["correct"] for r in rs) if rs else 0.0,
            "f1": statistics.fmean(r["f1"] for r in listy) if listy else None,
            "unsupported_rate": (sum(bool(r["unsupported_ids"]) for r in supported) / len(supported)) if supported else None,
        }

    by_group: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for r in records:
        by_group[group_key(r)].append(r)
    wall = [r["wall_s"] for r in records]
    service = [r.get("service_s", r["wall_s"]) for r in records]
    return {
        "overall": block(records),
        "groups": {k: block(v) for k, v in sorted(by_group.items())},
        "latency_p50_s": percentile(service, 50),
        "latency_p95_s": percentile(service, 95),
        "wall_p50_s": percentile(wall, 50),
        "wall_p95_s": percentile(wall, 95),
        "prompt_tokens_per_q": statistics.fmean(r["prompt_tokens"] for r in records) if records else 0.0,
        "completion_tokens_per_q": statistics.fmean(r["completion_tokens"] for r in records) if records else 0.0,
        "cost_usd_per_q": statistics.fmean(r["cost_usd"] for r in records) if records else 0.0,
        "errors": sum(bool(r["error"]) for r in records),
        "fell_back": sum(bool(r["fell_back"]) for r in records),
        "models": sorted({m for r in records for m in r["models"]}),
    }


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.1f}%"


def render_report(title: str, summary: dict[str, Any], notes: list[str]) -> str:
    lines = [f"# {title}", ""]
    lines += [f"- {n}" for n in notes] + [""]
    lines += ["| Question group | n | Accuracy (F1>=0.8 / exact) | Mean F1 | Cited IDs not in evidence |", "|---|---|---|---|---|"]
    for name, b in [*summary["groups"].items(), ("**overall**", summary["overall"])]:
        lines.append(f"| {name} | {b['n']} | {pct(b['accuracy'])} | {pct(b['f1'])} | {pct(b['unsupported_rate'])} |")
    s = summary
    lines += [
        "",
        (f"Service time per question: p50 {s['latency_p50_s']:.1f}s, p95 {s['latency_p95_s']:.1f}s (retrieval and model calls, without rate-limit waits); "
        f"wall clock p50 {s['wall_p50_s']:.1f}s, p95 {s['wall_p95_s']:.1f}s because the free tier allows only 8,000 tokens per minute. "
        f"Tokens per question: {s['prompt_tokens_per_q']:.0f} in / {s['completion_tokens_per_q']:.0f} out. "
        f"Reference cost: ${s['cost_usd_per_q']:.5f} per question (Groq list prices; the free tier costs nothing). "
        f"Query/answer errors: {s['errors']}. Questions that fell back to another model: {s['fell_back']}. Models used: {', '.join(s['models']) or 'none'}."),
        "",
    ]
    return "\n".join(lines)


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    cols = ["id", "type", "hops", "style", "correct", "f1", "precision", "recall", "order_exact", "said_not_found", "final_kind",
            "wall_s", "service_s", "waited_s", "prompt_tokens", "completion_tokens", "cost_usd", "models", "llm_calls", "rows", "error", "unsupported_ids", "question"]
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in records:
            w.writerow({**r, "models": "|".join(r["models"]), "unsupported_ids": "|".join(r["unsupported_ids"])})


def log_mlflow(run_name: str, params: dict[str, Any], summary: dict[str, Any], artifacts: list[Path]) -> None:
    """Best effort: a tracking problem must never cost a long evaluation run."""
    try:
        import mlflow

        mlflow.set_tracking_uri(f"sqlite:///{Path(__file__).resolve().parents[2] / 'mlflow.db'}")
        mlflow.set_experiment("redstring-baselines")
        with mlflow.start_run(run_name=run_name):
            mlflow.log_params({k: str(v)[:250] for k, v in params.items()})
            mlflow.log_metric("accuracy", summary["overall"]["accuracy"])
            if summary["overall"]["f1"] is not None:
                mlflow.log_metric("mean_f1", summary["overall"]["f1"])
            for k in ("latency_p50_s", "latency_p95_s", "cost_usd_per_q", "prompt_tokens_per_q", "completion_tokens_per_q"):
                mlflow.log_metric(k, summary[k])
            for name, b in summary["groups"].items():
                safe = name.replace(" ", "_").replace("(", "").replace(")", "").replace("-", "")
                mlflow.log_metric(f"acc_{safe}", b["accuracy"])
            for a in artifacts:
                mlflow.log_artifact(str(a))
    except Exception:
        log.exception("MLflow logging failed (results are saved on disk)")


# ------------------------------------------------------------------ running
def run_system(
    system: str,
    answer_fn: Callable[[GoldQuestion], SystemAnswer],
    questions: list[GoldQuestion],
    store: RunStore,
    allowed_models: set[str] | None = None,
) -> list[dict[str, Any]]:
    everything = store.load()
    done = store.load(allowed_models)
    discarded = len(everything) - len(done)
    todo = [q for q in questions if q.id not in done]
    log.info("%s: %d questions, %d already done, %d to run%s", system, len(questions), len(done), len(todo),
             f" ({discarded} earlier answers discarded: produced by a model outside this chain)" if discarded else "")
    for i, q in enumerate(todo, start=1):
        try:
            ans = answer_fn(q)
        except LLMError as exc:  # every model in the chain is unavailable: stop and keep progress, do not record junk
            raise SystemExit(f"Stopping after {i - 1} new answers: {exc}\nProgress is saved; rerun the same command to resume.") from exc
        except Exception as exc:  # one bad question must not lose a long run; recorded as an error
            log.exception("question %s failed", q.id)
            ans = SystemAnswer(text=f"ERROR: {exc!r}", error=repr(exc))
        rec = make_record(q, ans, system)
        store.append(rec)
        done[q.id] = rec
        log.info("[%d/%d] %s %-9s %s f1=%.2f %.1fs %d+%d tok %s", i, len(todo), q.id, q.type, "OK " if rec["correct"] else "BAD", rec["f1"],
                 rec["wall_s"], rec["prompt_tokens"], rec["completion_tokens"], rec["models"])
    return [done[q.id] for q in questions if q.id in done]


def main() -> None:
    from redstring_cti.graph.embeddings import load_model
    from redstring_cti.graph.loader import get_driver
    from redstring_cti.llm import GroqLLM
    from redstring_cti.retrieval import text2cypher, vector_rag

    parser = argparse.ArgumentParser(description="Evaluate a baseline on the gold set.")
    parser.add_argument("--system", choices=SYSTEM_NAMES, required=True)
    parser.add_argument("--split", choices=["dev", "test"], default="dev")
    parser.add_argument("--final", action="store_true", help="required for --split test: the held-out run, done once at the end")
    parser.add_argument("--ids", help="comma-separated question ids")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--run-name")
    parser.add_argument(
        "--llm-chain", default="groq-120b",
        help=f"model chain: one of {sorted(LLM_CHAINS)} or comma-separated specs such as "
        "'openrouter:minimax/minimax-m3.1-flash:free'. Non-default chains get their own run name.",
    )
    parser.add_argument("--include-fewshot", action="store_true", help="also score the few-shot example questions")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("neo4j").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    if args.split == "test" and not args.final:
        raise SystemExit("Refusing to run the held-out test split without --final. Do not tune against it.")

    gold = load_gold()
    exclude = set() if args.include_fewshot else set(text2cypher.FEWSHOT_IDS)  # same questions for every system
    questions = select_questions(gold, args.split, ids=args.ids.split(",") if args.ids else None, limit=args.limit, exclude=exclude)
    chain_tag, chain = resolve_chain(args.llm_chain)
    run_name = args.run_name or (f"{args.system}-{args.split}" + ("" if chain_tag == "groq-120b" else f"-{chain_tag}"))
    allowed = {record_name(m) for m in chain}
    store = RunStore(RUNS_DIR / run_name)

    driver = get_driver()
    llm = GroqLLM(models=chain)
    if any(m.startswith("openrouter:") for m in chain):
        b = llm._budget_limit
        log.info("OpenRouter free-model allowance today: %d of %d requests used; this run is resumable across days", b.used(), b.limit)
    try:
        if args.system == "vector_rag":
            embedder = load_model()
            records = run_system(args.system, lambda q: vector_rag.answer(llm, driver, embedder, q.question), questions, store, allowed)
        else:
            fewshot = text2cypher.build_fewshot(gold)
            records = run_system(args.system, lambda q: text2cypher.answer(llm, driver, fewshot, q.question), questions, store, allowed)
    finally:
        driver.close()

    summary = summarise(records)
    notes = [
        f"System: `{args.system}`; split: `{args.split}`; {len(records)} questions scored.",
        "Correct = ID F1 >= 0.8 (lists), exact number (counts), says not found (unanswerable). Ranked lists are scored as sets; order is reported in the per-question CSV.",
    ]
    if exclude:
        notes.append(f"The {len(exclude)} questions used as Text2Cypher few-shot examples are excluded for every system so tables are comparable.")
    if summary["fell_back"]:
        notes.append(f"WARNING: {summary['fell_back']} questions were answered by a fallback model, so this run mixes models.")
    report = RESULTS_DIR / f"{run_name}.md"
    report.write_text(render_report(f"{args.system} on the {args.split} split", summary, notes))
    csv_path = store.directory / "per_question.csv"
    write_csv(csv_path, records)
    log_mlflow(run_name, {"system": args.system, "split": args.split, "n": len(records), "models": summary["models"], "chain": chain_tag,
                          "fewshot": list(text2cypher.FEWSHOT_IDS) if args.system == "text2cypher" else ""}, summary, [csv_path, report])
    print(report.read_text())


if __name__ == "__main__":
    main()


# ------------------------------------------------------------------ comparing saved runs
def compare_runs(
    run_names: list[str], title: str, notes: list[str], *, models: set[str] | None = None, paired: bool = True
) -> str:
    """Side-by-side table of saved runs (reads results.jsonl; no model calls).

    `paired` keeps only questions every run answered validly, so the systems are compared like for like."""
    summaries: dict[str, dict[str, Any]] = {}
    loaded: dict[str, dict[str, dict[str, Any]]] = {}
    counts: dict[str, tuple[int, int]] = {}
    for name in run_names:
        loaded[name] = RunStore(RUNS_DIR / name).load(models)
        if not loaded[name]:
            raise SystemExit(f"no results found for run {name!r}")
    shared = set.intersection(*(set(r) for r in loaded.values())) if paired else None
    for name, recs in loaded.items():
        chosen = [r for i, r in recs.items() if shared is None or i in shared]
        summaries[name] = summarise(chosen)
        counts[name] = (len(chosen), len(recs))
    groups = sorted({g for s in summaries.values() for g in s["groups"]})
    head = "| Question group | " + " | ".join(f"{n} acc. | {n} F1" for n in run_names) + " |"
    lines = [f"# {title}", ""] + [f"- {n}" for n in notes] + ["", head, "|---|" + "---|---|" * len(run_names)]
    for g in [*groups, "overall"]:
        cells = []
        for n in run_names:
            b = summaries[n]["overall"] if g == "overall" else summaries[n]["groups"].get(g)
            cells += [pct(b["accuracy"]), pct(b["f1"])] if b else ["-", "-"]
            if b:
                cells[-2] += f" (n={b['n']})"
        lines.append(f"| {'**overall**' if g == 'overall' else g} | " + " | ".join(cells) + " |")
    lines += ["", "| Run | Service p50 | Service p95 | Tokens in/out per q | Reference $/q | Cited IDs not in evidence | Errors | Fallbacks |", "|---|---|---|---|---|---|---|---|"]
    for n, s in summaries.items():
        lines.append(
            f"| {n} | {s['latency_p50_s']:.1f}s | {s['latency_p95_s']:.1f}s | {s['prompt_tokens_per_q']:.0f}/{s['completion_tokens_per_q']:.0f} | "
            f"${s['cost_usd_per_q']:.5f} | {pct(s['overall']['unsupported_rate'])} | {s['errors']} | {s['fell_back']} |"
        )
    lines += ["", "Questions compared / answered validly per run: " + ", ".join(f"{n}: {c} of {t}" for n, (c, t) in counts.items()) + "."]
    return "\n".join(lines) + "\n"


def compare_main() -> None:
    parser = argparse.ArgumentParser(description="Compare saved evaluation runs side by side.")
    parser.add_argument("runs", nargs="+")
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "baselines.md")
    parser.add_argument("--title", default="Baseline comparison")
    parser.add_argument("--note", action="append", default=[], help="extra note line (repeatable)")
    parser.add_argument("--model", action="append", default=[], help="keep only answers from this model (repeatable)")
    args = parser.parse_args()
    notes = ["Same questions, same model, same scorer for every run; only questions answered by every run are compared (paired)."]
    text = compare_runs(args.runs, args.title, notes + args.note, models=set(args.model) or None)
    args.out.write_text(text)
    print(text)
