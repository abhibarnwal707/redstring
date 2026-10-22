from pathlib import Path
from types import SimpleNamespace

from redstring_cti import app
from redstring_cti.extractor import upsert
from redstring_cti.extractor.schema import Entity, Extraction, Technique


def test_rate_limiter_allows_the_limit_then_refuses_and_recovers() -> None:
    now = [0.0]
    limiter = app.RateLimiter(2, window_s=100, clock=lambda: now[0])
    assert limiter.allow("a") == (True, 0) and limiter.allow("a") == (True, 0)
    allowed, wait = limiter.allow("a")
    assert not allowed and 0 < wait <= 101
    assert limiter.allow("b") == (True, 0)  # another visitor is unaffected
    now[0] = 101.0
    assert limiter.allow("a") == (True, 0)  # the window slid past the old hits


def test_format_answer_shows_route_cost_entities_and_paths() -> None:
    result = SimpleNamespace(answer="APT29 uses T1566.\nFINAL: T1566", route="graph", pattern="neighbors", llm_calls=2, tool_calls=2, tokens=1500, cost_usd=0.0003,
                             latency_ms=2500.0, entities=[{"id": "G0016", "name": "APT29"}], verdict="pass", paths=[["G0016", "USES", "T1566"]])
    answer, trace = app.format_answer(result)
    assert "T1566" in answer and "graph / neighbors" in trace and "$0.00030" in trace and "G0016" in trace and "G0016 -[USES]-> T1566" in trace
    result.verdict, result.answer, result.paths, result.entities = "revise", "", [], []
    answer, trace = app.format_answer(result)
    assert answer == "No answer." and "Self-check" in trace


def test_extraction_preview_links_and_never_writes(driver) -> None:  # type: ignore[no-untyped-def]
    raw = Extraction(entities=[Entity(text="Cozy Bear", type="THREAT_ACTOR"), Entity(text="ZorgBot", type="MALWARE")], techniques=[Technique(attack_id="T1566.001")]).to_json()
    before = driver.execute_query("MATCH (n) WHERE n:Report OR n:ProvisionalEntity RETURN count(n) AS n")[0][0]["n"]
    out = app.run_extraction("Cozy Bear used ZorgBot. " * 5, lambda task, chunk: raw, driver, {"T1566.001"}, max_chunks=3)
    after = driver.execute_query("MATCH (n) WHERE n:Report OR n:ProvisionalEntity RETURN count(n) AS n")[0][0]["n"]
    assert "**G0016**" in out and "not in the graph" in out and "T1566.001" in out and before == after
    assert app.run_extraction("   ", lambda task, chunk: raw, driver, set(), 3) == "Paste some report text first."


def test_extraction_preview_says_when_it_truncated(driver) -> None:  # type: ignore[no-untyped-def]
    text = "\n\n".join(f"Paragraph number {i}. " * 80 for i in range(6))
    out = app.run_extraction(text, lambda task, chunk: '{"entities":[],"techniques":[]}', driver, set(), max_chunks=2)
    assert "Only the first 2 of" in out
    assert len(upsert.chunk_text(text)) > 2


def test_benchmarks_are_read_from_disk_and_missing_files_are_named(tmp_path: Path) -> None:
    (tmp_path / "extractor_comparison.md").write_text("# table")
    pages = app.benchmarks_markdown(tmp_path)
    assert pages["Extractor comparison"] == "# table" and "has not been generated" in pages["Retrieval baselines"]


def test_live_techniques_come_from_the_graph(driver) -> None:  # type: ignore[no-untyped-def]
    live = app.live_technique_ids(driver)
    assert len(live) == 706 and "T1566.001" in live and "T1086" not in live  # T1086 was revoked in favour of T1059.001
