"""RedString-CTI MCP server (FastMCP): read-only tools over the threat-intelligence knowledge graph.

Run over stdio:  uv run python -m redstring_cti.mcp_server.server     (or `make serve`)
Claude Code:     claude mcp add redstring -- uv --directory <repo> run python -m redstring_cti.mcp_server.server

Every tool is read-only (Cypher runs in read transactions behind a deny-list, with a timeout and row cap)
and every call is appended to data/processed/audit.jsonl.
"""

import logging
from collections.abc import Callable
from typing import Annotated, Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

from redstring_cti.mcp_server import tools
from redstring_cti.mcp_server.audit import AuditLog
from redstring_cti.mcp_server.guardrails import CypherExecutionError, GuardrailError

log = logging.getLogger(__name__)

INSTRUCTIONS = """\
Knowledge graph of cyber threat intelligence: MITRE ATT&CK v20 (groups, techniques, tactics, software,
mitigations, campaigns), CAPEC attack patterns, CWE weaknesses, and CVEs from NVD with CISA KEV flags.
All tools are read-only.

Typical use:
- Names to IDs: resolve_entity("Cozy Bear") -> G0016. Always do this before get_neighbors / find_paths.
  semantic_search matches meaning, not names; use it for descriptive questions ("abuse scheduled tasks").
- Facts about one thing: get_entity. Its direct links: get_neighbors. Multi-hop routes (e.g. Group -> CVE):
  find_paths. Anything else: cypher_query (read-only, row-capped).
- cve_lookup checks the graph first and falls back to NVD for CVEs that are not in the graph.

Important: Group/Technique -> CVE paths go through CAPEC and CWE and mean 'shares a weakness', never
'the group exploited this CVE'. Say so when you report them. Every result carries ids you can cite."""

READ_ONLY = {"readOnlyHint": True, "idempotentHint": True, "openWorldHint": False}
audit = AuditLog()
mcp = FastMCP("redstring-cti", instructions=INSTRUCTIONS)
_ctx: tools.Context | None = None
_embedder: Any = None


def _embed(text: str) -> list[float]:
    """Load the embedding model on first use (it takes a few seconds and imports torch)."""
    global _embedder
    from redstring_cti.graph.embeddings import embed_query, load_model

    if _embedder is None:
        _embedder = load_model()
    return embed_query(_embedder, text)


def get_context() -> tools.Context:
    global _ctx
    if _ctx is None:
        from redstring_cti.graph.loader import get_driver

        _ctx = tools.Context(driver=get_driver(), embed=_embed)
    return _ctx


def _run(name: str, args: dict[str, Any], fn: Callable[[tools.Context], Any]) -> Any:
    """Audit the call and turn caller-fixable errors into MCP tool errors."""
    def call() -> Any:
        try:
            return fn(get_context())
        except tools.ToolInputError as exc:
            raise ToolError(str(exc)) from exc
        except GuardrailError as exc:
            raise ToolError(f"query rejected: {exc}") from exc
        except CypherExecutionError as exc:
            raise ToolError(f"query failed: {exc}") from exc

    return audit.record(name, args, call)


@mcp.tool(annotations=READ_ONLY)
def semantic_search(
    query: Annotated[str, Field(description="Natural-language description of what to find, e.g. 'abuse scheduled tasks for persistence'.")],
    labels: Annotated[list[str] | None, Field(description="Restrict to node types: Group, Technique, Tactic, Software, Mitigation, Campaign, CAPEC, CWE, CVE. Default searches ATT&CK/CAPEC/CWE concepts; ['CVE'] searches CVEs.")] = None,
    k: Annotated[int, Field(description="Number of results (1-25).")] = 10,
) -> dict[str, Any]:
    """Find nodes whose meaning is closest to the query (vector search). Good for descriptive questions; it
    does NOT resolve bare names or aliases (use resolve_entity). CVE vectors cover KEV CVEs and CVEs on the
    Technique-CAPEC-CWE chain only."""
    return _run("semantic_search", {"query": query, "labels": labels, "k": k}, lambda c: tools.semantic_search(c, query, labels, k))


@mcp.tool(annotations=READ_ONLY)
def resolve_entity(
    name: Annotated[str, Field(description="A name or alias, e.g. 'Cozy Bear', 'Spearphishing Attachment', 'Log4Shell'.")],
    labels: Annotated[list[str] | None, Field(description="Optionally restrict to node types.")] = None,
    limit: Annotated[int, Field(description="Maximum candidates (1-20).")] = 5,
) -> dict[str, Any]:
    """Map a name or alias to graph IDs using the full-text index on names, aliases and descriptions.
    `exact` marks candidates whose name or alias equals the query. Several candidates can share a name."""
    return _run("resolve_entity", {"name": name, "labels": labels, "limit": limit}, lambda c: tools.resolve_entity(c, name, labels, limit))


@mcp.tool(annotations=READ_ONLY)
def get_entity(
    id: Annotated[str, Field(description="An ATT&CK, CAPEC, CWE or CVE id, e.g. T1566.001, G0016, S0154, M1017, TA0001, C0024, CAPEC-66, CWE-89, CVE-2021-44228.")],
) -> dict[str, Any]:
    """Properties of one node plus how many relationships of each type it has (outgoing and incoming)."""
    return _run("get_entity", {"id": id}, lambda c: tools.get_entity(c, id))


@mcp.tool(annotations=READ_ONLY)
def get_neighbors(
    id: Annotated[str, Field(description="Node id.")],
    rel_types: Annotated[list[str] | None, Field(description="Only these relationship types: USES, MITIGATES, SUBTECHNIQUE_OF, ATTRIBUTED_TO, IN_TACTIC, MAPS_TO, EXPLOITS, CHILD_OF, HAS_WEAKNESS.")] = None,
    direction: Annotated[str, Field(description="'out', 'in' or 'both'.")] = "both",
    limit: Annotated[int, Field(description="Maximum neighbours (1-200).")] = 50,
) -> dict[str, Any]:
    """Nodes directly connected to a node. Each neighbour comes with a [source, relationship, target] path
    triple; USES edges include the ATT&CK procedure text as `evidence`."""
    return _run("get_neighbors", {"id": id, "rel_types": rel_types, "direction": direction, "limit": limit}, lambda c: tools.get_neighbors(c, id, rel_types, direction, limit))


@mcp.tool(annotations=READ_ONLY)
def find_paths(
    from_id: Annotated[str, Field(description="Start node id, e.g. G0016.")],
    to_label: Annotated[str, Field(description="Type of node to reach: Group, Technique, Tactic, Software, Mitigation, Campaign, CAPEC, CWE or CVE.")],
    max_hops: Annotated[int, Field(description="Maximum relationships per path (1-4).")] = 4,
    limit: Annotated[int, Field(description="Maximum DISTINCT end nodes returned (1-200); each comes with up to two example paths.")] = 25,
    kev_only: Annotated[bool, Field(description="When the target is CVE, keep only CISA KEV (actively exploited) CVEs.")] = False,
) -> dict[str, Any]:
    """Distinct nodes of one type reachable from a node over multi-hop routes derived from the graph schema
    (for example Group -> Technique -> CAPEC -> CWE -> CVE), each with example paths as nodes and citable
    [source, relationship, target] triples. `endpoint_count` is the number of distinct results. Routes that go
    through CAPEC/CWE are weakness-level associations."""
    return _run("find_paths", {"from_id": from_id, "to_label": to_label, "max_hops": max_hops, "limit": limit, "kev_only": kev_only}, lambda c: tools.find_paths(c, from_id, to_label, max_hops, limit, kev_only))


@mcp.tool(annotations=READ_ONLY)
def cypher_query(
    cypher: Annotated[str, Field(description="A read-only Cypher query. Writes, admin procedures, unbounded paths and multiple statements are rejected; results are capped at 200 rows and 5 seconds.")],
) -> dict[str, Any]:
    """Run read-only Cypher against the graph. Use only when get_entity / get_neighbors / find_paths do not fit.
    Schema: (Group|Software|Campaign)-[:USES]->(Technique); (Mitigation)-[:MITIGATES]->(Technique);
    (Technique)-[:IN_TACTIC]->(Tactic); (CAPEC)-[:MAPS_TO]->(Technique); (CAPEC)-[:EXPLOITS]->(CWE);
    (CVE)-[:HAS_WEAKNESS]->(CWE). Keys: attack_id, capec_id, cwe_id, cve_id."""
    return _run("cypher_query", {"cypher": cypher}, lambda c: tools.cypher_query(c, cypher))


@mcp.tool(annotations={**READ_ONLY, "openWorldHint": True})
def cve_lookup(
    cve_id: Annotated[str, Field(description="CVE id, e.g. CVE-2021-44228.")],
    live: Annotated[bool, Field(description="If the CVE is not in the graph, look it up in NVD (cached for 24 hours).")] = True,
) -> dict[str, Any]:
    """Details of a CVE: score, KEV flag and weaknesses. Reads the graph first; for CVEs missing from the
    graph it can fetch the record live from NVD (never written to the graph)."""
    return _run("cve_lookup", {"cve_id": cve_id, "live": live}, lambda c: tools.cve_lookup(c, cve_id, live))


@mcp.tool(annotations=READ_ONLY)
def report_insights(
    report_id: Annotated[str | None, Field(description="Only this ingested report (ids look like report-840ed1775d3e).")] = None,
    entity_id: Annotated[str | None, Field(description="Only reports mentioning this group, software or campaign id, e.g. G0016 or S1073.")] = None,
) -> dict[str, Any]:
    """What ingested threat reports say compared with curated ATT&CK: per report and per curated actor/software, the
    techniques ATT&CK already records for it (`confirmed`) and those only the report asserts (`new`), plus entities the
    graph does not know. Report claims are automated extractions and unverified. Use for questions such as 'what does
    this advisory add beyond ATT&CK?'. With no arguments it summarises the most recent reports."""
    return _run("report_insights", {"report_id": report_id, "entity_id": entity_id}, lambda c: tools.report_insights(c, report_id, entity_id))


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    for noisy in ("neo4j", "mcp", "httpx"):
        logging.getLogger(noisy).setLevel(logging.ERROR)
    mcp.run(show_banner=False)  # stdio


if __name__ == "__main__":
    main()
