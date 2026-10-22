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


def test_missing_groq_key_is_detected_and_explained() -> None:
    assert app.agent_key_missing(None) and app.agent_key_missing("") and app.agent_key_missing("   ")
    assert not app.agent_key_missing("gsk_abc")
    assert "console.groq.com/keys" in app.NO_KEY_MESSAGE and ".env" in app.NO_KEY_MESSAGE


def test_final_line_is_hidden_and_not_found_is_explained() -> None:
    assert app.strip_final("APT29 uses T1566.\nFINAL: T1566") == "APT29 uses T1566."
    assert app.strip_final("**FINAL:** T1566\nSome text first") == "Some text first"
    assert app.strip_final("FINAL: NOT_FOUND") == app.NOT_FOUND_TEXT  # nothing else to show: say it in words
    assert app.strip_final("The graph has no EPSS data.\nFINAL: NOT_FOUND") == "The graph has no EPSS data."
    assert app.strip_final("") == ""


def test_cited_ids_get_names_in_a_compact_table() -> None:
    table = app.named_items(["T1566", "CVE-2024-1", "T1059"], {"T1566": "Phishing", "T1059": "Command and Scripting Interpreter"})
    assert "| T1566 | Phishing |" in table and "| T1059 |" in table and "CVE-2024-1" not in table  # CVEs carry no name
    assert app.named_items(["CVE-2024-1"], {}) == ""
    many = {f"T{i:04d}": f"Name {i}" for i in range(100)}
    assert "_and 60 more_" in app.named_items(list(many), many) and app.named_items(list(many), many).count("| T") == app.MAX_NAMED


def test_format_answer_shows_names_and_hides_the_protocol_line() -> None:
    result = SimpleNamespace(answer="APT29 uses these.\nFINAL: T1566", route="graph", pattern="neighbors", llm_calls=1, tool_calls=1, tokens=10, cost_usd=0.0,
                             latency_ms=10.0, entities=[], verdict="pass", paths=[], citations=["T1566"])
    answer, _ = app.format_answer(result, {"T1566": "Phishing"})
    assert "FINAL" not in answer and "| T1566 | Phishing |" in answer


def test_id_names_reads_real_names_from_the_graph(driver) -> None:  # type: ignore[no-untyped-def]
    names = app.id_names(driver, ["T1566.001", "G0016", "CVE-2021-44228", "M1017"])
    assert names["T1566.001"] == "Spearphishing Attachment" and names["G0016"] == "APT29" and "CVE-2021-44228" not in names
    assert app.id_names(driver, []) == {}
