from collections.abc import Iterator
from typing import Any

import pytest
from neo4j import Driver

from redstring_cti.extractor import upsert
from redstring_cti.extractor.schema import Entity, Extraction, Relation, Technique

RID = "report-TEST-upsert"


# ------------------------------------------------------------------ chunking (no database)
def test_chunks_respect_the_limit_and_lose_nothing() -> None:
    para = " ".join(f"Sentence number {i} says something about the intrusion." for i in range(60))
    text = para + "\n\n" + "A second paragraph. " * 40 + "\n\n" + "x" * 3000
    chunks = upsert.chunk_text(text, max_chars=500)
    assert all(len(c) <= 500 for c in chunks) and len(chunks) > 5
    joined = " ".join(chunks)
    assert "Sentence number 0 " in joined and "Sentence number 59 " in joined and joined.count("x") == 3000


def test_chunking_edge_cases() -> None:
    assert upsert.chunk_text("") == [] and upsert.chunk_text("   \n\n  ") == []
    assert upsert.chunk_text("One short report.") == ["One short report."]


def test_report_ids_are_stable_and_provisional_uids_normalised() -> None:
    assert upsert.report_id_for("https://x/y") == upsert.report_id_for("https://x/y") != upsert.report_id_for("https://x/z")
    assert upsert.provisional_uid("MALWARE", "Zorg-Bot 2.0!") == upsert.provisional_uid("MALWARE", "zorg bot 2 0") == "prov:malware:zorg-bot-2-0"


# ------------------------------------------------------------------ against the real graph
@pytest.fixture
def clean(driver: Driver) -> Iterator[None]:
    upsert.drop_report(driver, RID)
    yield
    upsert.drop_report(driver, RID)


def test_links_names_aliases_and_unknowns(driver: Driver) -> None:
    apt29 = upsert.link_entity(driver, "APT29", "THREAT_ACTOR")
    assert (apt29.node_id, apt29.curated, apt29.method) == ("G0016", True, "exact")
    alias = upsert.link_entity(driver, "Cozy Bear", "THREAT_ACTOR")
    assert alias.node_id == "G0016" and alias.method == "alias" and alias.confidence < 1.0
    assert upsert.link_entity(driver, "Mimikatz", "TOOL").label == "Software"
    assert upsert.link_entity(driver, "CVE-2021-44228", "CVE").curated
    unknown = upsert.link_entity(driver, "ZorgBot", "MALWARE")
    assert not unknown.curated and unknown.node_id == "prov:malware:zorgbot" and unknown.label == "ProvisionalEntity"
    assert not upsert.link_entity(driver, "CVE-1999-99999", "CVE").curated
    assert not upsert.link_entity(driver, "some-c2.example", "INFRASTRUCTURE").curated  # infrastructure is never linked to curated nodes


def test_a_name_of_the_wrong_type_is_not_linked(driver: Driver) -> None:
    assert not upsert.link_entity(driver, "APT29", "MALWARE").curated  # APT29 is a group, not software


def test_lucene_special_characters_do_not_break_linking(driver: Driver) -> None:
    for name in ['AT&T (v2)', 'a:b', 'x" OR "y', "[brackets]", "back\\slash", "tilde~", "wild*card?"]:
        assert not upsert.link_entity(driver, name, "MALWARE").curated


def extraction() -> Extraction:
    return Extraction(
        entities=[Entity(text="Cozy Bear", type="THREAT_ACTOR"), Entity(text="ZorgBot", type="MALWARE"), Entity(text="CVE-2021-44228", type="CVE")],
        techniques=[Technique(attack_id="T1566.001"), Technique(attack_id="T1059.001"), Technique(attack_id="T9999")],
        relations=[Relation(head="Cozy Bear", relation="USES", tail="T1566.001"), Relation(head="ZorgBot", relation="EXPLOITS", tail="CVE-2021-44228"),
                   Relation(head="Cozy Bear", relation="USES", tail="ZorgBot"), Relation(head="Cozy Bear", relation="USES", tail="T9999")],
    )


def count(driver: Driver, cypher: str, **params: Any) -> int:
    rows, _, _ = driver.execute_query(cypher, **params)
    return int(rows[0]["n"])


def test_ingest_links_separates_and_never_touches_curated_edges(driver: Driver, clean: None) -> None:
    curated_before = count(driver, "MATCH ()-[r]->() WHERE NOT type(r) IN ['MENTIONS','ASSERTS_TECHNIQUE','ASSERTED'] RETURN count(r) AS n")
    props_before = count(driver, "MATCH (g:Group {attack_id:'G0016'}) RETURN size(keys(g)) AS n")
    live = {"T1566.001", "T1059.001"}
    rep = upsert.ingest(driver, RID, "Test report", "test://x", "text", [extraction(), extraction()], chunks=3, invalid=1, live_techniques=live)
    assert rep.linked["Cozy Bear"].node_id == "G0016" and not rep.linked["ZorgBot"].curated
    assert rep.unknown_techniques == ["T9999"] and rep.techniques == {"T1566.001": 2, "T1059.001": 2}
    assert rep.skipped_relations == 2  # tail T9999 is not a live ATT&CK technique, once per chunk
    assert ("Cozy Bear", "USES", "T1566.001") in rep.asserted and ("ZorgBot", "EXPLOITS", "CVE-2021-44228") in rep.asserted

    assert count(driver, "MATCH (r:Report {report_id:$r})-[m:MENTIONS]->() RETURN count(m) AS n", r=RID) == 3
    assert count(driver, "MATCH (:Report {report_id:$r})-[:MENTIONS]->(g:Group {attack_id:'G0016'}) RETURN count(g) AS n", r=RID) == 1
    assert count(driver, "MATCH (:Report {report_id:$r})-[m:MENTIONS]->(g:Group {attack_id:'G0016'}) RETURN m.count AS n", r=RID) == 2
    assert count(driver, "MATCH (:Report {report_id:$r})-[:ASSERTS_TECHNIQUE]->(t) RETURN count(t) AS n", r=RID) == 2
    assert count(driver, "MATCH (p:ProvisionalEntity {uid:'prov:malware:zorgbot'}) RETURN count(p) AS n") == 1
    assert count(driver, "MATCH (:Group {attack_id:'G0016'})-[a:ASSERTED {report_id:$r}]->(:Technique {attack_id:'T1566.001'}) RETURN count(a) AS n", r=RID) == 1
    assert count(driver, "MATCH (:ProvisionalEntity)-[a:ASSERTED {report_id:$r}]->(:CVE {cve_id:'CVE-2021-44228'}) RETURN count(a) AS n", r=RID) == 1
    assert count(driver, "MATCH (:Group {attack_id:'G0016'})-[a:ASSERTED {report_id:$r}]->(:ProvisionalEntity) RETURN count(a) AS n", r=RID) == 1

    # curated knowledge is untouched: same edge count, no new properties, provisional nodes invisible to the indexes
    assert count(driver, "MATCH ()-[r]->() WHERE NOT type(r) IN ['MENTIONS','ASSERTS_TECHNIQUE','ASSERTED'] RETURN count(r) AS n") == curated_before
    assert count(driver, "MATCH (g:Group {attack_id:'G0016'}) RETURN size(keys(g)) AS n") == props_before
    assert count(driver, "MATCH (n) WHERE (n:Searchable OR n:Reference) AND (n:ProvisionalEntity OR n:Report) RETURN count(n) AS n") == 0

    again = upsert.ingest(driver, RID, "Test report", "test://x", "text", [extraction(), extraction()], chunks=3, invalid=1, live_techniques=live)
    assert again.asserted == rep.asserted
    assert count(driver, "MATCH (:Report {report_id:$r})-[m:MENTIONS]->() RETURN count(m) AS n", r=RID) == 3  # idempotent
    assert count(driver, "MATCH ()-[a:ASSERTED {report_id:$r}]->() RETURN count(a) AS n", r=RID) == 3


def test_dry_run_writes_nothing_and_drop_report_cleans_up(driver: Driver, clean: None) -> None:
    live = {"T1566.001", "T1059.001"}
    upsert.ingest(driver, RID, "t", "s", "x", [extraction()], 1, 0, live, dry_run=True)
    assert count(driver, "MATCH (r:Report {report_id:$r}) RETURN count(r) AS n", r=RID) == 0
    upsert.ingest(driver, RID, "t", "s", "x", [extraction()], 1, 0, live)
    removed = upsert.drop_report(driver, RID)
    assert removed == {"asserted_edges": 3, "provisional_entities": 1, "reports": 1}
    assert count(driver, "MATCH (p:ProvisionalEntity {uid:'prov:malware:zorgbot'}) RETURN count(p) AS n") == 0
    assert count(driver, "MATCH (g:Group {attack_id:'G0016'}) RETURN count(g) AS n") == 1  # curated node survives


def test_a_provisional_entity_shared_with_another_report_survives_a_drop(driver: Driver, clean: None) -> None:
    other = "report-TEST-upsert-other"
    live = {"T1566.001", "T1059.001"}
    try:
        upsert.ingest(driver, RID, "t", "s", "x", [extraction()], 1, 0, live)
        upsert.ingest(driver, other, "t", "s", "x", [extraction()], 1, 0, live)
        upsert.drop_report(driver, RID)
        assert count(driver, "MATCH (p:ProvisionalEntity {uid:'prov:malware:zorgbot'}) RETURN count(p) AS n") == 1
    finally:
        upsert.drop_report(driver, other)


def test_extract_report_counts_invalid_chunks() -> None:
    good = '{"entities":[],"techniques":[]}'
    outputs = iter([good, "garbage", good])
    text = "\n\n".join(["Paragraph one. " * 60, "Paragraph two. " * 60, "Paragraph three. " * 60])
    extractions, chunks, invalid, pruned = upsert.extract_report(text, lambda task, chunk: next(outputs))
    assert chunks == 3 and invalid == 1 and len(extractions) == 2 and pruned == 0


def test_prune_drops_unsupported_entities_and_their_relations() -> None:
    chunk = "Cozy Bear used ZorgBot. See advisory AA26-237A and CVE-2021-44228."
    parsed = Extraction(
        entities=[Entity(text="Cozy Bear", type="THREAT_ACTOR"), Entity(text="ZorgBot", type="MALWARE"), Entity(text="Invented", type="MALWARE"),
                  Entity(text="AA26-237A", type="CVE"), Entity(text="CVE-2021-44228", type="CVE")],
        techniques=[Technique(attack_id="T1566")],
        relations=[Relation(head="Cozy Bear", relation="USES", tail="ZorgBot"), Relation(head="Invented", relation="USES", tail="T1566"),
                   Relation(head="Cozy Bear", relation="USES", tail="T1566")],
    )
    clean, dropped = upsert.prune(parsed, chunk)
    assert [e.text for e in clean.entities] == ["Cozy Bear", "ZorgBot", "CVE-2021-44228"] and dropped == 2
    assert [(r.head, r.tail) for r in clean.relations or []] == [("Cozy Bear", "ZorgBot"), ("Cozy Bear", "T1566")]
    no_relations, _ = upsert.prune(Extraction(entities=[], techniques=[]), chunk)
    assert no_relations.relations is None


def test_salvage_keeps_the_valid_parts_of_a_flawed_output() -> None:
    from redstring_cti.extractor import metrics

    flawed = ('{"entities":[{"text":"The FBI","type":"ORGANIZATION"},{"text":"LockBit","type":"MALWARE"}],'
              '"techniques":[{"attack_id":"T1486"},{"attack_id":"banana"}],'
              '"relations":[{"head":"T1486","relation":"USES","tail":"T1486"},{"head":"LockBit","relation":"USES","tail":"T1486"},{"head":"Ghost","relation":"USES","tail":"T1486"}]}')
    assert metrics.parse(flawed) is None
    kept = metrics.salvage(flawed)
    assert kept is not None
    assert [e.text for e in kept.entities] == ["LockBit"] and [t.attack_id for t in kept.techniques] == ["T1486"]
    assert [(r.head, r.tail) for r in kept.relations or []] == [("LockBit", "T1486")]
    assert metrics.salvage('{"entities":[{"text":"x","type":"MALWARE"},{"text":"trunc') is None  # truncated JSON is beyond salvage
    assert metrics.salvage("not json") is None and metrics.salvage('{"entities":5,"techniques":[]}') is not None


# ------------------------------------------------------------------ report_insights tool and agent route
def seeded_report(driver: Driver) -> None:
    live = {"T1566.001", "T1059.001"}
    ex = Extraction(
        entities=[Entity(text="Cozy Bear", type="THREAT_ACTOR"), Entity(text="ZorgBot", type="MALWARE")],
        techniques=[Technique(attack_id="T1566.001"), Technique(attack_id="T1059.001")],
        relations=[Relation(head="Cozy Bear", relation="USES", tail="T1566.001"), Relation(head="Cozy Bear", relation="USES", tail="T1059.001")],
    )
    upsert.ingest(driver, RID, "Test advisory", "test://advisory", "x", [ex], 1, 0, live)


def test_report_insights_splits_confirmed_from_new(driver: Driver, clean: None) -> None:
    from redstring_cti.mcp_server import tools

    seeded_report(driver)
    ctx = tools.Context(driver=driver, embed=lambda text: [0.0] * 384)
    res = tools.report_insights(ctx, report_id=RID)
    (report,) = res["reports"]
    assert report["title"] == "Test advisory" and report["techniques_asserted"] == 2
    apt29 = next(e for e in report["entities"] if e["id"] == "G0016")
    confirmed = {t["id"] for t in apt29["confirmed"]}
    new = {t["id"] for t in apt29["new"]}
    # each asserted technique lands in exactly one bucket, according to ATT&CK's own USES edges
    assert confirmed | new == {"T1566.001", "T1059.001"} and not confirmed & new
    rows, _, _ = driver.execute_query("MATCH (:Group {attack_id:'G0016'})-[:USES]->(t:Technique) WHERE t.attack_id IN ['T1566.001','T1059.001'] RETURN t.attack_id AS id")
    assert confirmed == {r["id"] for r in rows}
    assert [p["name"] for p in report["provisional"]] == ["ZorgBot"]
    assert tools.report_insights(ctx, entity_id="G0016")["reports"][0]["report_id"] == RID
    assert all(r["report_id"] != RID for r in tools.report_insights(ctx, report_id="report-does-not-exist")["reports"])
    assert tools.report_insights(ctx, report_id="report-nope")["reports"] == []


def test_report_cues_do_not_hijack_ordinary_questions() -> None:
    from redstring_cti.agent.nodes import REPORT_CUES

    for q in ["Which techniques does APT29 use?", "Which mitigations apply to Phishing (T1566)?", "How many groups use T1059?", "Which groups share at least 21 techniques with APT29?"]:
        assert not REPORT_CUES.search(q), q
    for q in ["What does this advisory add beyond ATT&CK about Royal?", "What does the latest report say about LockBit?", "Which techniques does the ingested report assert for BianLian that ATT&CK lacks?",
              "Compare the new advisory with ATT&CK for Royal"]:
        assert REPORT_CUES.search(q), q


def test_llama_cpp_backend_builds_the_prompt_and_returns_the_text(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import sys
    import types

    from redstring_cti.extractor.backends import LlamaCppExtractor
    from redstring_cti.extractor.schema import SYSTEM_PROMPTS

    seen: dict[str, object] = {}

    class FakeLlama:
        def __init__(self, **kw: object) -> None:
            seen["init"] = kw

        def create_chat_completion(self, **kw: object) -> dict[str, object]:
            seen["call"] = kw
            return {"choices": [{"message": {"content": ' {"entities":[],"techniques":[]} '}}]}

    class FakeGrammar:
        @staticmethod
        def from_json_schema(schema: str) -> str:
            seen["schema"] = schema
            return "grammar"

    module = types.ModuleType("llama_cpp.llama_grammar")
    module.LlamaGrammar = FakeGrammar  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "llama_cpp", types.ModuleType("llama_cpp"))
    monkeypatch.setitem(sys.modules, "llama_cpp.llama_grammar", module)
    extractor = LlamaCppExtractor("model.gguf", {"T1566.001"}, llama_factory=FakeLlama)
    assert extractor("full", "Some report text.") == '{"entities":[],"techniques":[]}'
    call = seen["call"]
    assert isinstance(call, dict) and call["grammar"] == "grammar" and call["temperature"] == 0.0
    assert call["messages"][0]["content"] == SYSTEM_PROMPTS["full"]  # type: ignore[index]
    assert "T1566.001" in str(seen["schema"]) and '"relations"' in str(seen["schema"])
    extractor("entities_techniques", "x")
    assert '"relations"' not in str(seen["schema"])  # the second task gets its own grammar without relations
