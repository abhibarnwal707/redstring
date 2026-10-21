import json
import sys
from pathlib import Path
from typing import Any

import pytest
from fastmcp import Client
from fastmcp.client.transports import StdioTransport
from fastmcp.exceptions import ToolError
from neo4j import Driver

from redstring_cti.mcp_server import server, tools
from redstring_cti.mcp_server.audit import AuditLog

REPO = Path(__file__).resolve().parents[1]
EXPECTED_TOOLS = {"semantic_search", "resolve_entity", "get_entity", "get_neighbors", "find_paths", "cypher_query", "cve_lookup"}


@pytest.fixture
def wired(driver: Driver, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the server at the live test graph, a fake embedder (no torch) and a private audit log."""
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    log = tmp_path / "audit.jsonl"
    monkeypatch.setattr(server, "_ctx", tools.Context(driver=driver, embed=lambda text: [0.0] * 384, nvd_live=False, nvd_cache_dir=None))
    monkeypatch.setattr(server, "audit", AuditLog(log))
    return log


async def test_tools_are_listed_with_read_only_hints_and_documented_arguments(wired: Path) -> None:
    async with Client(server.mcp) as c:
        listed = await c.list_tools()
    assert {t.name for t in listed} == EXPECTED_TOOLS
    for t in listed:
        assert t.annotations and t.annotations.readOnlyHint is True and t.annotations.destructiveHint is not True
        assert t.description and len(t.description) > 40
        described = [p for p in t.inputSchema["properties"].values() if p.get("description")]
        assert len(described) == len(t.inputSchema["properties"]), f"{t.name}: every argument needs a description"
    assert next(t for t in listed if t.name == "cve_lookup").annotations.openWorldHint is True  # the only tool that can reach out
    assert "association" in (server.mcp.instructions or "") or "shares a weakness" in (server.mcp.instructions or "")


async def test_calls_return_structured_results_and_errors_are_clean(wired: Path) -> None:
    async with Client(server.mcp) as c:
        r = await c.call_tool("get_entity", {"id": "G0016"})
        assert r.structured_content and r.structured_content["properties"]["name"] == "APT29"
        res = await c.call_tool("resolve_entity", {"name": "Cozy Bear"})
        assert res.structured_content and res.structured_content["candidates"][0]["id"] == "G0016"
        paths = await c.call_tool("find_paths", {"from_id": "G0016", "to_label": "CVE", "limit": 2, "kev_only": True})
        assert paths.structured_content and len(paths.structured_content["paths"]) == 2
        for tool, args, fragment in [
            ("cypher_query", {"cypher": "MATCH (n) DETACH DELETE n"}, "query rejected"),
            ("cypher_query", {"cypher": "MATCH (a)-[:USES*]->(b) RETURN b"}, "unbounded"),
            ("get_entity", {"id": "APT29"}, "resolve_entity"),
            ("get_neighbors", {"id": "G0016", "direction": "sideways"}, "direction"),
            ("find_paths", {"from_id": "G0016", "to_label": "CVE", "max_hops": 9}, "max_hops"),
        ]:
            with pytest.raises(ToolError, match=fragment):
                await c.call_tool(tool, args)
        with pytest.raises(ToolError):  # schema validation happens before the tool runs
            await c.call_tool("get_entity", {"id": 5})


async def test_every_call_is_audited_including_failures(wired: Path) -> None:
    async with Client(server.mcp) as c:
        await c.call_tool("get_entity", {"id": "T1566.001"})
        await c.call_tool("get_neighbors", {"id": "G0016", "rel_types": ["USES"], "direction": "out", "limit": 4})
        await c.call_tool("get_entity", {"id": "T9999"})
        with pytest.raises(ToolError):
            await c.call_tool("cypher_query", {"cypher": "CREATE (:Hack)"})
    entries = [json.loads(line) for line in wired.read_text().splitlines()]
    assert [e["tool"] for e in entries] == ["get_entity", "get_neighbors", "get_entity", "cypher_query"]
    assert [e["ok"] for e in entries] == [True, True, True, False]
    assert entries[1]["rows"] == 4 and entries[1]["args"]["limit"] == 4
    assert entries[2]["rows"] == 0  # a miss is logged as zero rows: this is how tool "success with rows" is measured
    assert "GuardrailError" in entries[3]["error"] or "ToolError" in entries[3]["error"] or "not allowed" in entries[3]["error"]
    assert all(e["duration_ms"] >= 0 and e["ts"].endswith("+00:00") for e in entries)


async def test_audit_log_truncates_huge_arguments(wired: Path) -> None:
    async with Client(server.mcp) as c:
        with pytest.raises(ToolError):
            await c.call_tool("semantic_search", {"query": "x" * 900})
    entry = json.loads(wired.read_text().splitlines()[0])
    assert len(json.dumps(entry["args"])) < 700 and entry["ok"] is False


async def test_graph_is_unchanged_after_a_session_of_tool_calls(wired: Path, driver: Driver) -> None:
    def counts() -> tuple[int, int]:
        with driver.session() as s:
            return s.run("MATCH (n) RETURN count(n) AS c").single()["c"], s.run("MATCH ()-[r]->() RETURN count(r) AS c").single()["c"]  # type: ignore[index]

    before = counts()
    async with Client(server.mcp) as c:
        await c.call_tool("get_neighbors", {"id": "T1566.001"})
        await c.call_tool("find_paths", {"from_id": "G0016", "to_label": "CVE", "limit": 3})
        for attack in ("MATCH (n:Group) SET n.name = 'pwned'", "MATCH (n) DETACH DELETE n", "MERGE (:Hack)"):
            with pytest.raises(ToolError):
                await c.call_tool("cypher_query", {"cypher": attack})
    assert counts() == before


# ------------------------------------------------------------------ the real thing: a stdio subprocess
async def test_server_works_over_stdio_as_claude_would_launch_it(tmp_path: Path) -> None:
    """Spawns `python -m redstring_cti.mcp_server.server`, talks MCP over stdin/stdout, and exercises a tool that
    loads the embedding model (torch must not write anything to stdout and corrupt the protocol)."""
    audit_log = tmp_path / "stdio-audit.jsonl"
    transport = StdioTransport(
        command=sys.executable,
        args=["-m", "redstring_cti.mcp_server.server"],
        cwd=str(REPO),
        env={"REDSTRING_AUDIT_LOG": str(audit_log), "PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
    )
    async with Client(transport, timeout=120) as c:
        assert {t.name for t in await c.list_tools()} == EXPECTED_TOOLS
        entity = await c.call_tool("get_entity", {"id": "T1566.001"})
        assert entity.structured_content and entity.structured_content["found"]
        sem: Any = await c.call_tool("semantic_search", {"query": "abuse scheduled tasks for persistence", "k": 3})
        assert any(h["id"].startswith("T1053") for h in sem.structured_content["results"])
        with pytest.raises(ToolError, match="query rejected"):
            await c.call_tool("cypher_query", {"cypher": "MATCH (n) DETACH DELETE n"})
    tools_called = [json.loads(line)["tool"] for line in audit_log.read_text().splitlines()]
    assert tools_called == ["get_entity", "semantic_search", "cypher_query"]
