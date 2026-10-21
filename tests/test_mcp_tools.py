import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from neo4j import Driver

from redstring_cti.graph.embeddings import embed_query, load_model
from redstring_cti.graph.ids import parse_id
from redstring_cti.graph.metapaths import enumerate_metapaths, metapath_cypher
from redstring_cti.mcp_server import tools
from redstring_cti.mcp_server.guardrails import (
    MAX_ROWS,
    CypherExecutionError,
    GuardrailError,
)
from redstring_cti.mcp_server.tools import ToolInputError


# ------------------------------------------------------------------ pure pieces
@pytest.mark.parametrize(
    ("text", "label", "key"),
    [
        ("t1566.001", "Technique", "T1566.001"), ("TA0001", "Tactic", "TA0001"), ("G0016", "Group", "G0016"),
        ("S0154", "Software", "S0154"), ("M1017", "Mitigation", "M1017"), ("C0024", "Campaign", "C0024"),
        ("capec-66", "CAPEC", "CAPEC-66"), ("CWE-89", "CWE", "CWE-89"), ("cve-2021-44228", "CVE", "CVE-2021-44228"),
    ],
)
def test_parse_id(text: str, label: str, key: str) -> None:
    ref = parse_id(text)
    assert ref and (ref.label, ref.key, ref.uid) == (label, key, f"{label}:{key}")


@pytest.mark.parametrize("bad", ["APT29", "", "T12", "CVE-21-1", "G00160", "Technique:T1566", "T1566.1"])
def test_parse_id_rejects_names_and_malformed_ids(bad: str) -> None:
    assert parse_id(bad) is None


def test_metapaths_are_derived_from_the_schema() -> None:
    (route,) = enumerate_metapaths("Group", "CVE")
    assert route.hops == 4 and route.weakness_level
    assert route.describe() == "Group -USES-> Technique <-MAPS_TO- CAPEC -EXPLOITS-> CWE <-HAS_WEAKNESS- CVE"
    assert enumerate_metapaths("Group", "CVE", max_hops=3) == []  # needs four hops
    assert enumerate_metapaths("Group", "Group") == []
    mitigations = enumerate_metapaths("Group", "Mitigation")
    assert mitigations[0].hops == 2 and not mitigations[0].weakness_level
    assert [m.hops for m in mitigations] == sorted(m.hops for m in mitigations)  # shortest first
    assert all(len(set(m.labels)) == len(m.labels) for m in mitigations)  # simple routes only


def test_metapath_cypher_contains_only_whitelisted_pieces() -> None:
    (route,) = enumerate_metapaths("Technique", "CVE")
    cypher = metapath_cypher(route, kev_only=True)
    assert "$uid" in cypher and "n3.kev = true" in cypher
    assert all(f":{x}" in cypher for x in ("MAPS_TO", "EXPLOITS", "HAS_WEAKNESS"))
    assert "kev" not in metapath_cypher(route)
    (to_tech,) = enumerate_metapaths("Software", "Tactic", 2)
    assert "kev" not in metapath_cypher(to_tech, kev_only=True)  # the flag only applies to CVE targets


# ------------------------------------------------------------------ the tools, against the live graph
@pytest.fixture(scope="module")
def real_embed() -> Any:
    model = load_model()
    return lambda text: embed_query(model, text)


@pytest.fixture
def ctx(driver: Driver, real_embed: Any, tmp_path: Path) -> tools.Context:
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    return tools.Context(driver=driver, embed=real_embed, nvd_cache_dir=tmp_path / "nvd")


def test_get_entity(ctx: tools.Context) -> None:
    e = tools.get_entity(ctx, "t1566.001")
    assert e["found"] and e["label"] == "Technique" and e["properties"]["name"] == "Spearphishing Attachment"
    assert not {"embedding", "uid", "ingested_at", "stix_id"} & set(e["properties"])
    assert len(e["properties"]["description"]) <= tools.DETAIL_DESCRIPTION_CHARS
    assert e["relationship_counts"]["out"]["IN_TACTIC"] == 1 and e["relationship_counts"]["in"]["USES"] > 10
    assert tools.get_entity(ctx, "T9999") == {"found": False, "id": "T9999", "label": "Technique"}
    with pytest.raises(ToolInputError, match="resolve_entity"):
        tools.get_entity(ctx, "APT29")


def test_get_neighbors_directions_filters_and_orientation(ctx: tools.Context) -> None:
    out = tools.get_neighbors(ctx, "G0016", ["USES"], "out", 5)
    assert out["returned"] == 5 and out["truncated"] and all(p[0] == "G0016" and p[1] == "USES" for p in out["paths"])
    incoming = tools.get_neighbors(ctx, "T1566.001", ["USES"], "in", 5)
    assert all(p[2] == "T1566.001" for p in incoming["paths"]) and all(n["direction"] == "in" for n in incoming["neighbors"])
    assert any("evidence" in n for n in incoming["neighbors"])  # the ATT&CK procedure text
    both = tools.get_neighbors(ctx, "T1566.001", None, "both", 200)
    assert {"USES", "IN_TACTIC", "SUBTECHNIQUE_OF"} <= {n["rel"] for n in both["neighbors"]}
    small = tools.get_neighbors(ctx, "TA0001", None, "both", 1000 if False else 200)
    assert small["returned"] <= 200
    only = tools.get_neighbors(ctx, "T1566.001", ["IN_TACTIC"], "out")
    assert [n["id"] for n in only["neighbors"]] == ["TA0001"] and not only["truncated"]
    assert tools.get_neighbors(ctx, "T9999")["neighbors"] == []


@pytest.mark.parametrize(
    "kwargs", [{"direction": "sideways"}, {"rel_types": ["LIKES"]}, {"limit": 0}, {"limit": 201}],
)
def test_get_neighbors_validates_arguments(ctx: tools.Context, kwargs: dict[str, Any]) -> None:
    with pytest.raises(ToolInputError):
        tools.get_neighbors(ctx, "G0016", **kwargs)


def one(ctx: tools.Context, cypher: str, **params: Any) -> dict[str, Any]:
    rows, _ = tools.run_read(ctx.driver, cypher, params=params)
    return rows[0]


def triple_exists(ctx: tools.Context, triple: list[str]) -> bool:
    src, rel, dst = triple
    rows, _ = tools.run_read(ctx.driver, f"MATCH (a)-[r:{rel}]->(b) WHERE coalesce(a.attack_id, a.capec_id, a.cwe_id, a.cve_id) = $a "
                                          "AND coalesce(b.attack_id, b.capec_id, b.cwe_id, b.cve_id) = $b RETURN count(r) AS c", params={"a": src, "b": dst})
    return rows[0]["c"] >= 1


def test_find_paths_returns_real_citable_paths(ctx: tools.Context) -> None:
    r = tools.find_paths(ctx, "G0016", "CVE", 4, 6, kev_only=True)
    assert r["routes"] == ["Group -USES-> Technique <-MAPS_TO- CAPEC -EXPLOITS-> CWE <-HAS_WEAKNESS- CVE"]
    assert len(r["paths"]) == 6 and r["truncated"] and "association" in r["note"]
    for p in r["paths"]:
        assert p["nodes"][0]["id"] == "G0016" and p["nodes"][-1]["label"] == "CVE" and p["hops"] == 4
        assert all(triple_exists(ctx, t) for t in p["triples"])  # every claimed edge exists in the graph
        assert one(ctx, "MATCH (v:CVE {cve_id: $id}) RETURN v.kev AS k", id=p["nodes"][-1]["id"])["k"] is True


def test_find_paths_known_chain_and_edge_cases(ctx: tools.Context) -> None:
    r = tools.find_paths(ctx, "T1566.001", "CVE", 3, 50, kev_only=True)
    assert {p["nodes"][-1]["id"] for p in r["paths"]} == {"CVE-2024-38112", "CVE-2024-43461"}  # the only two KEV CVEs with CWE-451
    unfiltered = tools.find_paths(ctx, "T1566.001", "CVE", 3, 50)
    assert unfiltered["truncated"] and len(unfiltered["paths"]) == 50  # without the filter the cap bites
    assert tools.find_paths(ctx, "G0016", "CVE", 3)["paths"] == [] and "No schema route" in tools.find_paths(ctx, "G0016", "CVE", 3)["note"]
    assert "No schema route" in tools.find_paths(ctx, "G0016", "Group")["note"]
    assert tools.find_paths(ctx, "G9999", "CVE")["paths"] == []  # unknown but well-formed start
    mit = tools.find_paths(ctx, "G0016", "Mitigation", 4, 10)
    assert mit["paths"] and "note" not in mit and mit["paths"][0]["hops"] == 2
    with pytest.raises(ToolInputError, match="unknown to_label"):
        tools.find_paths(ctx, "G0016", "Banana")
    bad_args: list[dict[str, Any]] = [{"max_hops": 5}, {"max_hops": 0}, {"limit": 0}, {"limit": 51}]
    for bad in bad_args:
        with pytest.raises(ToolInputError):
            tools.find_paths(ctx, "G0016", "CVE", **bad)


def test_cypher_query_is_guarded(ctx: tools.Context) -> None:
    ok = tools.cypher_query(ctx, "MATCH (s:Software) RETURN s.attack_id AS id ORDER BY id")  # 842 software nodes > the 200-row cap
    assert ok["row_count"] == MAX_ROWS and ok["truncated"] and ok["executed"].endswith(f"LIMIT {MAX_ROWS}")
    node = tools.cypher_query(ctx, "MATCH (t:Technique {attack_id: 'T1566.001'}) RETURN t")["rows"][0]["t"]
    assert node["name"] == "Spearphishing Attachment" and "embedding" not in node and node["labels"] == ["Technique"]
    vec = tools.cypher_query(ctx, "MATCH (t:Technique {attack_id: 'T1566.001'}) RETURN t.embedding AS e")["rows"][0]["e"]
    assert vec == "<vector omitted>"
    for bad in ("MATCH (n) DETACH DELETE n", "CREATE (:X)", "MATCH (a)-[:USES*]->(b) RETURN b", "CALL dbms.listConfig()", "MATCH (n) RETURN n; MATCH (m) RETURN m"):
        with pytest.raises(GuardrailError):
            tools.cypher_query(ctx, bad)
    with pytest.raises(CypherExecutionError):
        tools.run_read(ctx.driver, "UNWIND range(1, 1000000000) AS x RETURN sum(x) AS s", timeout_s=1.0)


NVD_RECORD = {
    "vulnerabilities": [{"cve": {
        "id": "CVE-2099-0001", "vulnStatus": "Analyzed", "published": "2099-01-01T00:00:00.000", "lastModified": "2099-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "A made-up flaw for tests."}],
        "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}, {"lang": "en", "value": "NVD-CWE-Other"}]}],
    }}]
}


def nvd_ctx(ctx: tools.Context, handler: Any) -> tuple[tools.Context, list[str]]:
    calls: list[str] = []

    def wrapped(req: httpx.Request) -> httpx.Response:
        calls.append(str(req.url))
        return handler(req)

    return tools.Context(driver=ctx.driver, embed=ctx.embed, http=httpx.Client(transport=httpx.MockTransport(wrapped)), nvd_cache_dir=ctx.nvd_cache_dir), calls


def test_cve_lookup_prefers_the_graph(ctx: tools.Context) -> None:
    c, calls = nvd_ctx(ctx, lambda r: httpx.Response(500))
    r = tools.cve_lookup(c, "cve-2024-38112")
    assert r["source"] == "graph" and r["in_graph"] and r["properties"]["kev"] is True
    assert r["weaknesses"][0]["id"] == "CWE-451" and calls == []  # never touched the network


def test_cve_lookup_falls_back_to_cached_live_nvd(ctx: tools.Context) -> None:
    c, calls = nvd_ctx(ctx, lambda r: httpx.Response(200, json=NVD_RECORD))
    first = tools.cve_lookup(c, "CVE-2099-0001")
    assert first["source"] == "nvd_live" and first["in_graph"] is False and first["properties"]["cvss_score"] == 9.8
    assert [w["id"] for w in first["weaknesses"]] == ["CWE-79"] and first["properties"]["kev"] is None  # pseudo-CWE filtered
    again = tools.cve_lookup(c, "CVE-2099-0001")
    assert again["source"] == "nvd_live" and len(calls) == 1  # second call served from the cache
    c2, calls2 = nvd_ctx(ctx, lambda r: httpx.Response(200, json=NVD_RECORD))
    assert tools.cve_lookup(c2, "CVE-2099-0001", live=False) == {"found": False, "id": "CVE-2099-0001", "in_graph": False, "live_checked": False}
    assert calls2 == []
    assert one(ctx, "MATCH (v:CVE {cve_id: 'CVE-2099-0001'}) RETURN count(v) AS c")["c"] == 0  # live results are never written to the graph


def test_cve_lookup_edge_cases(ctx: tools.Context, tmp_path: Path) -> None:
    c, _ = nvd_ctx(ctx, lambda r: httpx.Response(200, json={"vulnerabilities": []}))
    assert tools.cve_lookup(c, "CVE-2099-0002")["found"] is False
    rejected = {"vulnerabilities": [{"cve": {"id": "CVE-2099-0003", "vulnStatus": "Rejected", "descriptions": []}}]}
    c, _ = nvd_ctx(ctx, lambda r: httpx.Response(200, json=rejected))
    assert tools.cve_lookup(c, "CVE-2099-0003")["properties"] == {"vuln_status": "Rejected"}
    c, _ = nvd_ctx(ctx, lambda r: httpx.Response(429))
    with pytest.raises(ToolInputError, match="rate limit"):
        tools.cve_lookup(c, "CVE-2099-0004")
    with pytest.raises(ToolInputError, match="not a CVE"):
        tools.cve_lookup(ctx, "T1566")


def test_resolve_entity(ctx: tools.Context) -> None:
    r = tools.resolve_entity(ctx, "Cozy Bear")
    assert r["candidates"][0]["id"] == "G0016" and r["candidates"][0]["exact"] and r["candidates"][0]["matched_alias"] == "Cozy Bear"
    only_groups = tools.resolve_entity(ctx, "Cozy Bear", ["Group"])
    assert [c["label"] for c in only_groups["candidates"]] == ["Group"]
    names = tools.resolve_entity(ctx, "Spearphishing Attachment", ["Technique"])
    assert {c["id"] for c in names["candidates"] if c["exact"]} == {"T1566.001", "T1598.002"}  # two techniques share the name
    for weird in ('C++ (test) [x] "quoted" \\ back/slash', "a:b*c?", "~~~"):
        assert isinstance(tools.resolve_entity(ctx, weird)["candidates"], list)  # query syntax never breaks the search
    assert tools.resolve_entity(ctx, "zzzzqqqqxxxx")["candidates"] == []
    with pytest.raises(ToolInputError):
        tools.resolve_entity(ctx, "   ")


def test_semantic_search(ctx: tools.Context) -> None:
    r = tools.semantic_search(ctx, "abuse scheduled tasks for persistence", k=5)
    assert r["indexes"] == ["ref_vec"] and any(h["id"].startswith("T1053") for h in r["results"])
    assert [h["score"] for h in r["results"]] == sorted((h["score"] for h in r["results"]), reverse=True)
    groups = tools.semantic_search(ctx, "Russian espionage group", ["Group"], 5)
    assert groups["results"] and {h["label"] for h in groups["results"]} == {"Group"}
    cves = tools.semantic_search(ctx, "Windows MSHTML spoofing", ["CVE"], 3)
    assert cves["indexes"] == ["cve_vec"] and {h["label"] for h in cves["results"]} == {"CVE"}
    both = tools.semantic_search(ctx, "phishing", ["Technique", "CVE"], 10)
    assert both["indexes"] == ["ref_vec", "cve_vec"] and len(both["results"]) <= 10
    assert all(len(h["description"] or "") <= tools.DESCRIPTION_CHARS for h in r["results"])
    for bad in ({"query": ""}, {"query": "x" * 501}, {"query": "x", "k": 0}, {"query": "x", "k": 26}, {"query": "x", "labels": ["Banana"]}):
        with pytest.raises(ToolInputError):
            tools.semantic_search(ctx, **bad)


def test_no_tool_can_change_the_graph(ctx: tools.Context) -> None:
    def counts() -> tuple[int, int]:
        return one(ctx, "MATCH (n) RETURN count(n) AS c")["c"], one(ctx, "MATCH ()-[r]->() RETURN count(r) AS c")["c"]

    before = counts()
    tools.get_entity(ctx, "G0016"), tools.get_neighbors(ctx, "G0016"), tools.find_paths(ctx, "G0016", "CVE", 4, 5)
    tools.resolve_entity(ctx, "Cozy Bear"), tools.semantic_search(ctx, "phishing"), tools.cypher_query(ctx, "MATCH (n:Group) RETURN n.name LIMIT 5")
    for attack in ("MATCH (n) DETACH DELETE n", "MATCH (n:Group) SET n.name = 'x'", "CREATE (:Hack)", "MERGE (:Hack)"):
        with pytest.raises(GuardrailError):
            tools.cypher_query(ctx, attack)
    assert counts() == before


def test_tool_output_stays_compact(ctx: tools.Context) -> None:
    sizes = {
        "get_entity": tools.get_entity(ctx, "T1566.001"),
        "get_neighbors": tools.get_neighbors(ctx, "G0016", None, "both", 25),
        "find_paths": tools.find_paths(ctx, "G0016", "CVE", 4, 10),
        "semantic_search": tools.semantic_search(ctx, "phishing", k=10),
    }
    for name, payload in sizes.items():
        assert len(json.dumps(payload)) < 14_000, name  # a few thousand tokens at most
