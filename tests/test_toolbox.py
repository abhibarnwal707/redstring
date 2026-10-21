from pathlib import Path

import pytest
from neo4j import Driver

from redstring_cti.agent.toolbox import DirectToolbox, McpToolbox, ToolCallError
from redstring_cti.mcp_server import tools

pytestmark = pytest.mark.filterwarnings("ignore::ResourceWarning")


@pytest.fixture
def direct(driver: Driver) -> DirectToolbox:
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    box = DirectToolbox(tools.Context(driver=driver, embed=lambda t: [0.0] * 384, nvd_live=False, nvd_cache_dir=None))
    box.close = lambda: None  # type: ignore[method-assign]  # the shared test driver must stay open
    return box


def test_direct_toolbox_returns_dicts_and_raises_typed_errors(direct: DirectToolbox) -> None:
    assert direct.call("get_entity", {"id": "G0016"})["properties"]["name"] == "APT29"
    with pytest.raises(ToolCallError, match="resolve_entity"):
        direct.call("get_entity", {"id": "APT29"})
    with pytest.raises(ToolCallError, match="query rejected"):
        direct.call("cypher_query", {"cypher": "MATCH (n) DETACH DELETE n"})
    with pytest.raises(ToolCallError, match="unknown tool"):
        direct.call("drop_database", {})
    with pytest.raises(ToolCallError, match="bad arguments"):
        direct.call("get_entity", {"identifier": "G0016"})


def test_mcp_toolbox_is_a_persistent_stdio_session(driver: Driver, tmp_path: Path) -> None:
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    log = tmp_path / "audit.jsonl"
    box = McpToolbox(env={"REDSTRING_AUDIT_LOG": str(log)})
    try:
        assert box.call("get_entity", {"id": "G0016"})["properties"]["name"] == "APT29"
        cand = box.call("resolve_entity", {"name": "Cozy Bear"})["candidates"][0]
        assert cand["id"] == "G0016" and cand["exact"]
        paths = box.call("find_paths", {"from_id": "G0016", "to_label": "CVE", "limit": 2, "kev_only": True})
        assert len(paths["paths"]) == 2
        with pytest.raises(ToolCallError, match="query rejected"):
            box.call("cypher_query", {"cypher": "CREATE (:Hack)"})
        with pytest.raises(ToolCallError, match="resolve_entity"):
            box.call("get_entity", {"id": "APT29"})
        names = {t.name for t in box.langchain_tools()}
        assert {"find_paths", "resolve_entity", "cypher_query"} <= names  # also usable as LangChain tools
    finally:
        box.close()
    import json

    calls = [json.loads(line) for line in log.read_text().splitlines()]
    assert [c["tool"] for c in calls[:3]] == ["get_entity", "resolve_entity", "find_paths"]  # one server process saw them all
    assert [c["ok"] for c in calls] == [True, True, True, False, False]
