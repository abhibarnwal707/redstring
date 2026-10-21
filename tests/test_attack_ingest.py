from pathlib import Path

import pytest
from neo4j import Driver

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.graph.loader import apply_schema
from redstring_cti.ingest.attack import load_attack, parse_attack
from redstring_cti.ingest.common import strip_markup

FIXTURE = Path(__file__).parent / "fixtures" / "attack_mini.json"
REAL = RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"


def test_strip_markup() -> None:
    raw = "[APT29](https://attack.mitre.org/groups/G0016) used X.(Citation: A (2021))(Citation: B)"
    assert strip_markup(raw) == "APT29 used X."
    assert strip_markup(None) is None


def test_parse_fixture_filters_and_maps() -> None:
    g = parse_attack(FIXTURE, "test")
    ids = {(n.label, n.key) for n in g.nodes}
    assert ("Group", "G-TEST-1") in ids
    assert not {k for _, k in ids} & {"G-TEST-2", "G-TEST-3", "T-TEST-2"}  # deprecated / revoked skipped
    assert g.stats["skipped_deprecated:intrusion-set"] == 1
    assert g.stats["skipped_revoked:intrusion-set"] == 1
    assert g.stats["skipped_deprecated:attack-pattern"] == 1

    assert g.stats["nodes:Technique"] == 3 and g.stats["nodes:Software"] == 2
    assert g.stats["edges:USES"] == 4  # r1-r4; r8, r9 (not live) and r10 (invalid pair) dropped
    assert g.stats["edges_dropped_endpoint_not_live:USES"] == 2
    assert g.stats["edges_dropped_invalid_pair:USES:Technique->Group"] == 1
    assert g.stats["edges:MITIGATES"] == g.stats["edges:SUBTECHNIQUE_OF"] == 1
    assert g.stats["edges:ATTRIBUTED_TO"] == 1
    assert g.stats["edges:IN_TACTIC"] == 3 and g.stats["in_tactic_unresolved"] == 1  # 'detects' ignored

    group = next(n for n in g.nodes if n.key == "G-TEST-1")
    assert group.props["description"] == "Fixture Bear is a group."
    assert group.props["aliases"] == ["Fixture Bear", "Cozy Fixture"]
    uses = next(e for e in g.edges if e.rel == "USES" and e.dst_key == "T-TEST-1.001")
    assert uses.props["description"] == "Fixture Bear used spearphishing."


@pytest.mark.skipif(not REAL.exists(), reason="run `make download` first")
def test_parse_real_bundle_counts() -> None:
    g = parse_attack(REAL, ATTACK_VERSION)
    s = g.stats
    assert (s["nodes:Technique"], s["nodes:Group"], s["nodes:Software"]) == (706, 178, 842)
    assert (s["nodes:Mitigation"], s["nodes:Campaign"], s["nodes:Tactic"]) == (44, 57, 15)
    assert (s["edges:USES"], s["edges:MITIGATES"]) == (18975, 1477)
    assert (s["edges:SUBTECHNIQUE_OF"], s["edges:ATTRIBUTED_TO"]) == (479, 26)
    assert s["edges:IN_TACTIC"] >= 706 and "in_tactic_unresolved" not in s
    assert len({n.uid for n in g.nodes}) == len(g.nodes)  # uids are unique
    leaked = [n.key for n in g.nodes if "(Citation:" in n.props.get("description", "")]
    assert not leaked


def test_load_is_idempotent(driver: Driver) -> None:
    graph = parse_attack(FIXTURE, "test")
    apply_schema(driver)
    with driver.session() as session:  # never overwrite or delete real data
        clash = session.run(
            "MATCH (n) WHERE n.attack_id CONTAINS '-TEST-' AND n.source_version <> 'test' "
            "RETURN count(n) AS c"
        ).single()
    assert clash and clash["c"] == 0

    def snapshot() -> tuple[int, int]:
        with driver.session() as session:
            n = session.run("MATCH (n {source_version: 'test'}) RETURN count(n) AS c").single()
            e = session.run(
                "MATCH (a {source_version: 'test'})-[r]->() RETURN count(r) AS c"
            ).single()
        assert n and e
        return n["c"], e["c"]

    try:
        load_attack(driver, graph)
        first = snapshot()
        load_attack(driver, graph)
        assert snapshot() == first == (10, 10)
        with driver.session() as session:
            rec = session.run(
                "MATCH (t:Technique {attack_id: 'T-TEST-1.001'}) RETURN labels(t) AS l, t.uid AS uid"
            ).single()
        assert rec and "Searchable" in rec["l"] and rec["uid"] == "Technique:T-TEST-1.001"
    finally:
        with driver.session() as session:
            session.run(
                "MATCH (n {source_version: 'test'}) WHERE n.attack_id CONTAINS '-TEST-' DETACH DELETE n"
            ).consume()
