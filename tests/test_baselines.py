from pathlib import Path
from typing import Any

import pytest
from neo4j import Driver

from redstring_cti.evaluation import (
    RunStore,
    group_key,
    make_record,
    percentile,
    select_questions,
    summarise,
)
from redstring_cti.gold.models import GOLD_PATH, GoldQuestion, load_gold
from redstring_cti.llm import LLMResult
from redstring_cti.retrieval import text2cypher
from redstring_cti.retrieval.common import SystemAnswer

GOLD = load_gold() if GOLD_PATH.exists() else []


def result(text: str, model: str = "openai/gpt-oss-120b", prompt: int = 100, completion: int = 50) -> LLMResult:
    return LLMResult(text=text, model=model, prompt_tokens=prompt, completion_tokens=completion, reasoning_tokens=0, latency_s=0.5)


class FakeLLM:
    """Returns scripted replies in order and records the messages it was sent."""

    def __init__(self, replies: list[str]) -> None:
        self.replies = list(replies)
        self.sent: list[list[dict[str, str]]] = []

    def complete(self, messages: list[dict[str, str]], **_: Any) -> LLMResult:
        self.sent.append(messages)
        return result(self.replies.pop(0))


# ------------------------------------------------------------------ few-shot hygiene
@pytest.mark.skipif(not GOLD, reason="run `make gold` first")
def test_fewshot_examples_are_dev_questions_and_excluded_from_scoring() -> None:
    by_id = {q.id: q for q in GOLD}
    assert all(by_id[i].split == "dev" for i in text2cypher.FEWSHOT_IDS)
    prompt = text2cypher.build_fewshot(GOLD)
    assert all(by_id[i].question in prompt for i in text2cypher.FEWSHOT_IDS)
    test_questions = [q.question for q in GOLD if q.split == "test"]
    assert not any(t in prompt for t in test_questions)  # nothing from the held-out set
    scored = select_questions(GOLD, "dev", exclude=set(text2cypher.FEWSHOT_IDS))
    assert len(scored) == 120 - len(text2cypher.FEWSHOT_IDS)
    assert not {q.id for q in scored} & set(text2cypher.FEWSHOT_IDS)


@pytest.mark.skipif(not GOLD, reason="run `make gold` first")
def test_fewshot_covers_the_main_query_patterns() -> None:
    types = {q.type for q in GOLD if q.id in text2cypher.FEWSHOT_IDS}
    styles = {q.answer_style for q in GOLD if q.id in text2cypher.FEWSHOT_IDS}
    assert {"single_hop", "multi_hop", "aggregation"} <= types and {"list", "ranked_list", "count"} <= styles


def test_extract_cypher() -> None:
    assert text2cypher.extract_cypher("Here:\n```cypher\nMATCH (n) RETURN n\n```\nDone") == "MATCH (n) RETURN n"
    assert text2cypher.extract_cypher("```\nRETURN 1\n```") == "RETURN 1"
    assert text2cypher.extract_cypher("MATCH (n) RETURN n") == "MATCH (n) RETURN n"


def test_rows_for_prompt_truncates() -> None:
    rows: list[dict[str, object]] = [{"id": f"T{i:04d}", "x": "y" * 500} for i in range(100)]
    text = text2cypher.rows_for_prompt(rows)
    assert text.count("\n") == text2cypher.MAX_ROWS_IN_PROMPT and "40 more rows not shown" in text
    assert len(text.splitlines()[0]) < 260


# ------------------------------------------------------------------ Text2Cypher with a fake model, real database
def test_text2cypher_runs_the_generated_query_and_verbalises(driver: Driver) -> None:
    llm = FakeLLM([
        "```cypher\nMATCH (m:Mitigation)-[:MITIGATES]->(:Technique {attack_id: 'T1486'}) RETURN DISTINCT m.attack_id AS id ORDER BY id\n```",
        "T1486 is mitigated by M1040 and M1053.\nFINAL: M1040, M1053",
    ])
    ans = text2cypher.answer(llm, driver, "EXAMPLES", "Which mitigations address T1486?")  # type: ignore[arg-type]
    assert ans.rows == 2 and ans.error is None and len(ans.calls) == 2
    assert set(ans.evidence_ids) == {"M1040", "M1053"}
    assert "LIMIT 200" in (ans.cypher or "")
    assert "EXAMPLES" in llm.sent[0][0]["content"] and "T1486" in llm.sent[1][1]["content"]


def test_text2cypher_retries_once_with_the_error_message(driver: Driver) -> None:
    llm = FakeLLM([
        "```cypher\nMATCH (n RETURN n\n```",
        "```cypher\nMATCH (g:Group {attack_id: 'G0016'}) RETURN g.attack_id AS id\n```",
        "APT29 is G0016.\nFINAL: G0016",
    ])
    ans = text2cypher.answer(llm, driver, "", "Which group is APT29?")  # type: ignore[arg-type]
    assert ans.error is None and ans.rows == 1 and len(ans.calls) == 3
    retry_prompt = llm.sent[1][-1]["content"]
    assert "That query failed" in retry_prompt  # the model was told why


def test_text2cypher_refuses_writes_and_reports_the_error(driver: Driver) -> None:
    bad = "```cypher\nMATCH (n) DETACH DELETE n\n```"
    llm = FakeLLM([bad, bad])
    ans = text2cypher.answer(llm, driver, "", "Delete everything")  # type: ignore[arg-type]
    assert ans.error and "not allowed" in ans.error and ans.rows is None
    assert ans.text.startswith("ERROR") and len(ans.calls) == 2  # no verbalise call after a failed query
    with driver.session() as s:
        assert s.run("MATCH (n:Technique) RETURN count(n) AS c").single()["c"] == 706  # type: ignore[index]


# ------------------------------------------------------------------ evaluation plumbing
def q(style: str = "list", qtype: str = "single_hop", ids: list[str] | None = None, hops: int = 1) -> GoldQuestion:
    unans = style == "not_found"
    return GoldQuestion(
        id="q001", question="Which mitigations apply to T1486?", type="unanswerable" if unans else qtype, hops=0 if unans else hops,  # type: ignore[arg-type]
        answer_style=style, gold_ids=ids if ids is not None else ([] if unans else ["M1040"]), gold_values=["3"] if style == "count" else [],  # type: ignore[arg-type]
        gold_cypher="RETURN 1", split="dev",
    )


def test_make_record_scores_and_flags_unsupported_ids() -> None:
    ans = SystemAnswer(text="M1040 and M9999.\nFINAL: M1040", evidence_ids=["M1040"], calls=[result("x")], wall_s=2.0)
    rec = make_record(q(), ans, "vector_rag")
    assert rec["correct"] and rec["unsupported_ids"] == ["M9999"] and rec["cost_usd"] > 0 and rec["models"] == ["openai/gpt-oss-120b"]


def test_group_key_and_percentile() -> None:
    assert group_key({"type": "multi_hop", "hops": 3, "style": "list"}) == "multi_hop (3-hop)"
    assert group_key({"type": "aggregation", "hops": 1, "style": "count"}) == "aggregation (count)"
    assert percentile([1, 2, 3, 4, 5], 50) == 3 and percentile([], 95) == 0.0
    assert percentile([0, 10], 95) == pytest.approx(9.5)


def test_summarise_by_group() -> None:
    recs = [
        make_record(q(), SystemAnswer(text="FINAL: M1040", evidence_ids=["M1040"], calls=[result("x")], wall_s=1.0), "s"),
        make_record(q(), SystemAnswer(text="FINAL: M1999", evidence_ids=[], calls=[result("x")], wall_s=3.0), "s"),
        make_record(q("not_found"), SystemAnswer(text="FINAL: NOT_FOUND", calls=[result("x")], wall_s=2.0), "s"),
    ]
    s = summarise(recs)
    assert s["overall"]["n"] == 3 and s["overall"]["accuracy"] == pytest.approx(2 / 3)
    assert s["groups"]["single_hop"]["n"] == 2 and s["groups"]["single_hop"]["accuracy"] == 0.5
    assert s["groups"]["unanswerable"]["accuracy"] == 1.0
    assert s["latency_p50_s"] == 2.0 and s["models"] == ["openai/gpt-oss-120b"]


def test_run_store_is_resumable(tmp_path: Path) -> None:
    store = RunStore(tmp_path / "run")
    assert store.load() == {}
    store.append({"id": "q001", "x": 1})
    store.append({"id": "q002", "x": 2})
    assert set(RunStore(tmp_path / "run").load()) == {"q001", "q002"}


def test_select_questions_filters() -> None:
    gold = [q().model_copy(update={"id": f"q{i:03d}", "split": "test" if i % 5 == 0 else "dev"}) for i in range(1, 21)]
    dev = select_questions(gold, "dev")
    assert len(dev) == 16 and all(x.split == "dev" for x in dev)
    assert [x.id for x in select_questions(gold, "dev", ids=["q001", "q005"])] == ["q001"]  # q005 is test
    assert len(select_questions(gold, "dev", limit=3)) == 3
    assert "q001" not in {x.id for x in select_questions(gold, "dev", exclude={"q001"})}


def test_test_split_requires_the_final_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys

    from redstring_cti import evaluation

    monkeypatch.setattr(sys, "argv", ["x", "--system", "vector_rag", "--split", "test"])
    with pytest.raises(SystemExit, match="--final"):
        evaluation.main()


def test_compare_runs_builds_a_side_by_side_table(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redstring_cti import evaluation

    monkeypatch.setattr(evaluation, "RUNS_DIR", tmp_path)
    for name, text in (("a", "FINAL: M1040"), ("b", "FINAL: M1999")):
        store = RunStore(tmp_path / name)
        store.append(make_record(q(), SystemAnswer(text=text, evidence_ids=["M1040"], calls=[result("x")], wall_s=1.0), name))
    table = evaluation.compare_runs(["a", "b"], "T", ["note"])
    assert "| single_hop | 100.0% (n=1) | 100.0% | 0.0% (n=1) | 0.0% |" in table
    assert "| **overall** |" in table and "Reference $/q" in table
    with pytest.raises(SystemExit):
        evaluation.compare_runs(["missing"], "T", [])


def test_resolve_chain() -> None:
    from redstring_cti.config import LLM_CHAINS
    from redstring_cti.evaluation import resolve_chain

    assert resolve_chain("groq") == ("groq", LLM_CHAINS["groq"])
    assert resolve_chain("groq+openrouter")[1][-1].startswith("openrouter:")
    assert resolve_chain("openrouter:a/b:free, openai/gpt-oss-20b") == ("custom", ("openrouter:a/b:free", "openai/gpt-oss-20b"))
    with pytest.raises(SystemExit):
        resolve_chain(" , ")


# ------------------------------------------------------------------ quota exhaustion and model purity
from redstring_cti.llm import LLMError, record_name


def rec(qid: str, models: list[str], correct: bool = True) -> dict[str, Any]:
    gold = q().model_copy(update={"id": qid})
    ans = SystemAnswer(text="FINAL: M1040" if correct else "FINAL: M9", evidence_ids=["M1040"], calls=[result("x", model=m) for m in models], wall_s=1.0)
    return make_record(gold, ans, "s")


def test_record_name() -> None:
    assert record_name("openai/gpt-oss-120b") == "openai/gpt-oss-120b"
    assert record_name("groq:openai/gpt-oss-120b") == "openai/gpt-oss-120b"
    assert record_name("openrouter:a/b:free") == "openrouter:a/b:free"


def test_default_evaluation_chain_is_a_single_model() -> None:
    from redstring_cti.config import LLM_CHAINS, LLM_MODELS

    assert LLM_CHAINS["groq-120b"] == (LLM_MODELS[0],) and len(LLM_CHAINS["groq"]) == 3


def test_store_load_ignores_answers_from_other_models(tmp_path: Path) -> None:
    store = RunStore(tmp_path)
    store.append(rec("q001", ["openai/gpt-oss-120b"]))
    store.append(rec("q002", ["qwen/qwen3.8-27b"]))
    store.append(rec("q003", ["openai/gpt-oss-120b", "qwen/qwen3.8-27b"]))  # mixed within one question
    assert set(store.load()) == {"q001", "q002", "q003"}
    assert set(store.load({"openai/gpt-oss-120b"})) == {"q001"}


def test_resume_reruns_questions_answered_by_a_disallowed_model(tmp_path: Path) -> None:
    from redstring_cti.evaluation import run_system

    store = RunStore(tmp_path)
    store.append(rec("q001", ["qwen/qwen3.8-27b"], correct=False))  # earlier, fallback-model answer
    questions = [q().model_copy(update={"id": "q001"}), q().model_copy(update={"id": "q002"})]
    asked: list[str] = []

    def answer(question: GoldQuestion) -> SystemAnswer:
        asked.append(question.id)
        return SystemAnswer(text="FINAL: M1040", evidence_ids=["M1040"], calls=[result("x")], wall_s=1.0)

    out = run_system("s", answer, questions, store, {"openai/gpt-oss-120b"})
    assert asked == ["q001", "q002"] and all(r["correct"] for r in out)
    assert set(store.load({"openai/gpt-oss-120b"})) == {"q001", "q002"}  # the newer q001 record replaced it


def test_run_stops_cleanly_when_every_model_is_exhausted(tmp_path: Path) -> None:
    from redstring_cti.evaluation import run_system

    store = RunStore(tmp_path)
    questions = [q().model_copy(update={"id": f"q{i:03d}"}) for i in range(1, 6)]

    def answer(question: GoldQuestion) -> SystemAnswer:
        if question.id == "q003":
            raise LLMError("all models failed: daily quota")
        return SystemAnswer(text="FINAL: M1040", evidence_ids=["M1040"], calls=[result("x")], wall_s=1.0)

    with pytest.raises(SystemExit, match="rerun the same command to resume"):
        run_system("s", answer, questions, store)
    assert set(store.load()) == {"q001", "q002"}  # progress kept, no junk error rows for q003..q005
    resumed = run_system("s", lambda x: SystemAnswer(text="FINAL: M1040", calls=[result("x")], wall_s=1.0), questions, store)
    assert len(resumed) == 5


def test_other_exceptions_are_recorded_and_the_run_continues(tmp_path: Path) -> None:
    from redstring_cti.evaluation import run_system

    def answer(question: GoldQuestion) -> SystemAnswer:
        if question.id == "q002":
            raise ValueError("bad row")
        return SystemAnswer(text="FINAL: M1040", calls=[result("x")], wall_s=1.0)

    out = run_system("s", answer, [q().model_copy(update={"id": f"q{i:03d}"}) for i in (1, 2, 3)], RunStore(tmp_path))
    assert [r["error"] is not None for r in out] == [False, True, False]


def test_compare_is_paired_on_shared_questions(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redstring_cti import evaluation

    monkeypatch.setattr(evaluation, "RUNS_DIR", tmp_path)
    for qid in ("q001", "q002", "q003"):
        RunStore(tmp_path / "full").append(rec(qid, ["openai/gpt-oss-120b"]))
    for qid in ("q002", "q003"):
        RunStore(tmp_path / "partial").append(rec(qid, ["openai/gpt-oss-120b"], correct=False))
    RunStore(tmp_path / "partial").append(rec("q009", ["qwen/qwen3.8-27b"]))
    table = evaluation.compare_runs(["full", "partial"], "T", [], models={"openai/gpt-oss-120b"})
    assert "full: 2 of 3" in table and "partial: 2 of 2" in table  # only q002/q003 are shared; Qwen answer excluded
    unpaired = evaluation.compare_runs(["full", "partial"], "T", [], models={"openai/gpt-oss-120b"}, paired=False)
    assert "full: 3 of 3" in unpaired


# ------------------------------------------------------------------ network timeouts
def test_transport_timeouts_are_logged_and_limited(caplog: pytest.LogCaptureFixture) -> None:
    import httpx

    from redstring_cti.llm import GroqLLM

    attempts = []

    def handler(req: httpx.Request) -> httpx.Response:
        attempts.append(1)
        raise httpx.ReadTimeout("stuck", request=req)

    sleeps: list[float] = []
    llm = GroqLLM(models=("a",), api_key="k", cache_dir=None, client=httpx.Client(transport=httpx.MockTransport(handler)), sleep=sleeps.append)
    with caplog.at_level("WARNING"), pytest.raises(LLMError):
        llm.complete([{"role": "user", "content": "hi"}])
    assert len(attempts) == 3 and sleeps == [2.0, 4.0]  # two retries, then give up instead of waiting for minutes
    assert "ReadTimeout (attempt 1/3)" in caplog.text


def test_agent_stats_appear_in_the_report() -> None:
    from redstring_cti.evaluation import render_report, summarise

    def agent_record(route: str, verdict: str, tools: int) -> dict[str, Any]:
        r = make_record(q(), SystemAnswer(text="FINAL: M1040", evidence_ids=["M1040"], calls=[result("x"), result("y")], wall_s=1.0,
                                          extra={"route": route, "verdict": verdict, "tool_calls": tools, "budget_exhausted": []}), "agent")
        return r

    s = summarise([agent_record("graph", "pass", 2), agent_record("vector", "fail", 3)])
    assert s["agent"] == {"routes": {"graph": 1, "vector": 1}, "tool_calls_per_q": 2.5, "llm_calls_per_q": 2.0,
                          "verdicts": {"fail": 1, "pass": 1}, "budget_exhausted": 0}
    assert "Agent: routes" in render_report("t", s, [])
    plain = summarise([make_record(q(), SystemAnswer(text="FINAL: M1040", calls=[result("x")], wall_s=1.0), "vector_rag")])
    assert plain["agent"] is None and "Agent:" not in render_report("t", plain, [])


def test_rescore_applies_the_current_scorer_to_stored_answers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from redstring_cti import evaluation

    gold = q(ids=["CAPEC-90"])
    stale = make_record(gold, SystemAnswer(text="It is the pattern CAPEC-90 in the data. FINAL: CAPEC-90", evidence_ids=["CAPEC-90"], calls=[result("x")], wall_s=1.0), "s")
    stale.update(correct=False, f1=0.0, final_kind="none", unsupported_ids=["CAPEC-1"])  # as an older scorer would have recorded it
    fresh = evaluation.rescore(stale, gold)
    assert fresh["correct"] and fresh["f1"] == 1.0 and fresh["final_kind"] == "ids"
    assert fresh["unsupported_ids"] == ["CAPEC-1"] and stale["correct"] is False  # faithfulness kept, original untouched

    monkeypatch.setattr(evaluation, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(evaluation, "load_gold", lambda: [gold])
    RunStore(tmp_path / "old").append(stale)
    assert "| single_hop | 0.0% (n=1) | 0.0% |" in evaluation.compare_runs(["old"], "T", [])
    assert "| single_hop | 100.0% (n=1) | 100.0% |" in evaluation.compare_runs(["old"], "T", [], rescored=True)
