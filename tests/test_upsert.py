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
