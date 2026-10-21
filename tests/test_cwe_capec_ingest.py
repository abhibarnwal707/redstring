from pathlib import Path

import pytest
from neo4j import Driver

from redstring_cti.config import RAW_DIR
from redstring_cti.graph.loader import apply_schema
from redstring_cti.ingest.attack import load_attack, parse_attack
from redstring_cti.ingest.capec import load_capec, normalise_technique_id, parse_capec
from redstring_cti.ingest.cwe import load_cwe, parse_cwe

FIXTURES = Path(__file__).parent / "fixtures"
CWE_REAL = RAW_DIR / "cwec_latest.xml.zip"
CAPEC_REAL = RAW_DIR / "capec_latest.xml"


def test_normalise_technique_id() -> None:
    assert normalise_technique_id("1574.010") == "T1574.010"
    assert normalise_technique_id("T1574") == "T1574"


def test_parse_cwe_fixture() -> None:
    g = parse_cwe(FIXTURES / "cwe_mini.xml")
    assert g.version == "test"
    assert {n.key for n in g.nodes} == {"CWE-TEST-1", "CWE-TEST-2"}  # deprecated skipped, category ignored
    assert g.stats["skipped_deprecated:Weakness"] == 1
    root = next(n for n in g.nodes if n.key == "CWE-TEST-1")
    assert root.props["description"] == "A root weakness spread over lines."
    assert root.props["abstraction"] == "Class"
    assert len(g.edges) == 1  # two views collapse to one edge; PeerOf ignored; deprecated parent dropped
    assert (g.edges[0].src_key, g.edges[0].dst_key) == ("CWE-TEST-2", "CWE-TEST-1")
    assert g.edges[0].props["views"] == ["1000", "1003"]
    assert g.stats["edges_dropped_endpoint_not_kept:CHILD_OF"] == 1


def test_parse_capec_fixture() -> None:
    g = parse_capec(FIXTURES / "capec_mini.xml")
    assert g.version == "test"
    assert {n.key for n in g.nodes} == {"CAPEC-TEST-1", "CAPEC-TEST-2"}
    assert g.stats["skipped_deprecated:Attack_Pattern"] == 1
    assert g.stats["skipped_obsolete:Attack_Pattern"] == 1
    assert g.stats["edges_parsed:EXPLOITS"] == 2
    assert g.stats["edges_parsed:MAPS_TO"] == 2  # WASC mapping ignored
    assert g.stats["edges_parsed:CHILD_OF"] == 1  # parent TEST-3 is deprecated
    assert g.stats["edges_dropped_endpoint_not_kept:CHILD_OF"] == 1
    maps = {e.dst_key for e in g.edges if e.rel == "MAPS_TO"}
    assert maps == {"T-TEST-1.001", "T-TEST-404"}
    pattern = next(n for n in g.nodes if n.key == "CAPEC-TEST-1")
    assert (pattern.props["likelihood"], pattern.props["severity"]) == ("High", "Medium")


@pytest.mark.skipif(not CWE_REAL.exists(), reason="run `make download` first")
def test_parse_real_cwe_counts() -> None:
    g = parse_cwe(CWE_REAL)
    assert g.version == "4.20"
    assert g.stats["nodes:CWE"] == 944 and g.stats["skipped_deprecated:Weakness"] == 25
    assert g.stats["edges:CHILD_OF"] == 1160
    assert len({n.uid for n in g.nodes}) == len(g.nodes)


@pytest.mark.skipif(not CAPEC_REAL.exists(), reason="run `make download` first")
def test_parse_real_capec_counts() -> None:
    g = parse_capec(CAPEC_REAL)
    assert g.version == "3.9"
    assert g.stats["nodes:CAPEC"] == 558
    assert g.stats["skipped_deprecated:Attack_Pattern"] == 56
    assert g.stats["skipped_obsolete:Attack_Pattern"] == 1
    assert g.stats["edges_parsed:CHILD_OF"] == 532
    assert g.stats["edges_parsed:EXPLOITS"] == 1211
    assert g.stats["edges_parsed:MAPS_TO"] == 271
    assert all(e.dst_key.startswith("T") for e in g.edges if e.rel == "MAPS_TO")


def test_load_chain_is_idempotent(driver: Driver, isolated_test_graph: None) -> None:
    apply_schema(driver)

    def load_all() -> dict[str, int]:
        load_attack(driver, parse_attack(FIXTURES / "attack_mini.json", "test"))
        load_cwe(driver, parse_cwe(FIXTURES / "cwe_mini.xml"))
        return load_capec(driver, parse_capec(FIXTURES / "capec_mini.xml"))

    def snapshot() -> tuple[int, int]:
        with driver.session() as session:
            n = session.run("MATCH (n {source_version: 'test'}) RETURN count(n) AS c").single()
            e = session.run("MATCH (a {source_version: 'test'})-[r]->() RETURN count(r) AS c").single()
        assert n and e
        return n["c"], e["c"]

    dropped = load_all()
    first = snapshot()
    load_all()
    assert snapshot() == first == (14, 15)  # 10+2+2 nodes; 10+1+4 edges
    assert dropped == {"edges_dropped_endpoint_missing:MAPS_TO": 1}  # T-TEST-404 does not exist

    with driver.session() as session:
        rows = session.run(
            """MATCH (:CAPEC {capec_id: 'CAPEC-TEST-1'})-[m:MAPS_TO]->(t:Technique)
               RETURN t.attack_id AS id, m.via AS via"""
        ).data()
    assert rows == [{"id": "T-TEST-1.001", "via": ["capec"]}]
