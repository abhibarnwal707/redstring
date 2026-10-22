"""The tool implementations behind the MCP server. Plain functions over a `Context`, so they are
testable without MCP. All of them are read-only. Outputs are compact on purpose: every token a tool
returns costs latency and money downstream.

Errors that the caller can fix raise `ToolInputError`; the server turns them into MCP tool errors.
"""

import json
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from neo4j import Driver
from neo4j.graph import Node as Neo4jNode
from neo4j.graph import Path as Neo4jPath
from neo4j.graph import Relationship

from redstring_cti.config import PROCESSED_DIR
from redstring_cti.graph.ids import LABELS, key_expr, parse_id
from redstring_cti.graph.metapaths import MAX_HOPS, enumerate_metapaths, metapath_cypher
from redstring_cti.ingest.nvd import parse_cve
from redstring_cti.mcp_server.guardrails import MAX_ROWS, run_read, run_read_ex

MAX_K = 25
MAX_NEIGHBORS = 200
MAX_ENDPOINTS = 200  # find_paths limit counts distinct end nodes, not paths
EXAMPLES_PER_ENDPOINT = 2
DESCRIPTION_CHARS = 200
DETAIL_DESCRIPTION_CHARS = 600
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_MIN_INTERVAL_S = 6.5  # NVD allows 5 requests per 30 s without an API key
NVD_TTL_S = 24 * 3600
REL_TYPES = (
    "USES", "MITIGATES", "SUBTECHNIQUE_OF", "ATTRIBUTED_TO", "IN_TACTIC",
    "MAPS_TO", "EXPLOITS", "CHILD_OF", "HAS_WEAKNESS",
)
HIDDEN_PROPS = {"embedding", "embedding_key", "embedding_model", "ingested_at", "source", "source_version", "stix_id", "uid"}
_LUCENE_SPECIAL = re.compile(r'([+\-&|!(){}\[\]^"~*?:\\/])')
WEAKNESS_NOTE = (
    "Routes through CAPEC and CWE connect the start and end nodes only by a shared weakness: "
    "an association, not evidence that the start node (a group or technique) was used with the end node."
)


class ToolInputError(ValueError):
    """The arguments are wrong in a way the caller can fix."""


@dataclass
class Context:
    driver: Driver
    embed: Callable[[str], list[float]]
    http: httpx.Client | None = None
    nvd_live: bool = True
    nvd_cache_dir: Path | None = PROCESSED_DIR / "nvd_cache"
    _last_nvd_call: float = field(default=0.0, repr=False)


# ------------------------------------------------------------------ helpers
def short(text: Any, limit: int = DESCRIPTION_CHARS) -> str | None:
    if text is None:
        return None
    s = " ".join(str(text).split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def node_id(props: dict[str, Any]) -> str | None:
    return props.get("attack_id") or props.get("capec_id") or props.get("cwe_id") or props.get("cve_id")


def jsonable(value: Any) -> Any:
    """Neo4j result values -> compact JSON-safe values (vectors and long text are shortened)."""
    if isinstance(value, Neo4jNode):
        props = {k: jsonable(v) for k, v in value.items() if k not in HIDDEN_PROPS}
        return {"labels": [label for label in value.labels if label not in ("Searchable", "Reference")], **props}
    if isinstance(value, Relationship):
        return {"type": value.type, **{k: jsonable(v) for k, v in value.items() if k != "source"}}
    if isinstance(value, Neo4jPath):
        return [
            [node_id(dict(r.start_node)) if r.start_node else None, r.type, node_id(dict(r.end_node)) if r.end_node else None]
            for r in value.relationships
        ]
    if isinstance(value, list):
        if len(value) > 50 and all(isinstance(x, float) for x in value[:5]):
            return "<vector omitted>"
        return [jsonable(v) for v in value[:100]]
    if isinstance(value, dict):
        return {k: jsonable(v) for k, v in value.items()}
    if isinstance(value, str):
        return short(value, 300)
    return value


def _ref(entity_id: str) -> Any:
    ref = parse_id(entity_id)
    if ref is None:
        raise ToolInputError(
            f"{entity_id!r} is not an ATT&CK / CAPEC / CWE / CVE identifier (e.g. T1566.001, G0016, CAPEC-66, "
            "CWE-89, CVE-2021-44228). Use resolve_entity to find the ID for a name."
        )
    return ref


def _check_labels(labels: list[str] | None) -> list[str] | None:
    if labels is None:
        return None
    bad = [x for x in labels if x not in LABELS]
    if bad:
        raise ToolInputError(f"unknown labels {bad}; valid labels: {list(LABELS)}")
    return labels


def _bounded(name: str, value: int, low: int, high: int) -> int:
    if not low <= value <= high:
        raise ToolInputError(f"{name} must be between {low} and {high}, got {value}")
    return value


def _rows(ctx: Context, cypher: str, **params: Any) -> list[dict[str, Any]]:
    rows, _ = run_read(ctx.driver, cypher, params=params)
    return rows


# ------------------------------------------------------------------ tools
def semantic_search(ctx: Context, query: str, labels: list[str] | None = None, k: int = 10) -> dict[str, Any]:
    if not query.strip():
        raise ToolInputError("query is empty")
    if len(query) > 500:
        raise ToolInputError("query is longer than 500 characters")
    _bounded("k", k, 1, MAX_K)
    wanted = _check_labels(labels)
    if wanted is None:
        indexes = ["ref_vec"]
    elif set(wanted) == {"CVE"}:
        indexes = ["cve_vec"]
    elif "CVE" in wanted:
        indexes = ["ref_vec", "cve_vec"]
    else:
        indexes = ["ref_vec"]
    vec = ctx.embed(query)
    fetch = min(k * 5, 100) if wanted else k
    hits: list[dict[str, Any]] = []
    for index in indexes:
        rows = _rows(
            ctx,
            "CALL db.index.vector.queryNodes($index, $k, $vec) YIELD node, score "
            "RETURN node.uid AS uid, [l IN labels(node) WHERE NOT l IN ['Searchable', 'Reference']][0] AS label, "
            "node.name AS name, node.description AS description, score",
            index=index, k=fetch, vec=vec,
        )
        for r in rows:
            if wanted is None or r["label"] in wanted:
                hits.append({"id": r["uid"].split(":", 1)[1], "label": r["label"], "name": r["name"],
                             "description": short(r["description"]), "score": round(float(r["score"]), 4)})
    hits.sort(key=lambda h: -h["score"])
    return {"query": query, "indexes": indexes, "results": hits[:k]}


def get_entity(ctx: Context, id: str) -> dict[str, Any]:
    ref = _ref(id)
    rows = _rows(
        ctx,
        "MATCH (n:Searchable {uid: $uid}) OPTIONAL MATCH (n)-[r]-() "
        "RETURN properties(n) AS props, type(r) AS rel, startNode(r) = n AS outgoing, count(r) AS c",
        uid=ref.uid,
    )
    if not rows:
        return {"found": False, "id": ref.key, "label": ref.label}
    props = {k: v for k, v in rows[0]["props"].items() if k not in HIDDEN_PROPS}
    for key in ("description", "detection"):
        if key in props:
            props[key] = short(props[key], DETAIL_DESCRIPTION_CHARS)
    if isinstance(props.get("aliases"), list):
        props["aliases"] = props["aliases"][:20]
    degree: dict[str, dict[str, int]] = {"out": {}, "in": {}}
    for r in rows:
        if r["rel"]:
            degree["out" if r["outgoing"] else "in"][r["rel"]] = r["c"]
    return {"found": True, "id": ref.key, "label": ref.label, "properties": props, "relationship_counts": degree}


def get_neighbors(ctx: Context, id: str, rel_types: list[str] | None = None, direction: str = "both", limit: int = 50) -> dict[str, Any]:
    ref = _ref(id)
    if direction not in ("in", "out", "both"):
        raise ToolInputError("direction must be 'in', 'out' or 'both'")
    _bounded("limit", limit, 1, MAX_NEIGHBORS)
    types = list(rel_types) if rel_types else list(REL_TYPES)
    bad = [t for t in types if t not in REL_TYPES]
    if bad:
        raise ToolInputError(f"unknown relationship types {bad}; valid: {list(REL_TYPES)}")
    pattern = {"out": "(n)-[r]->(m)", "in": "(n)<-[r]-(m)", "both": "(n)-[r]-(m)"}[direction]
    rows = _rows(
        ctx,
        f"MATCH (n:Searchable {{uid: $uid}}) MATCH {pattern} WHERE type(r) IN $types "
        f"RETURN {key_expr('m')} AS id, [l IN labels(m) WHERE NOT l IN ['Searchable', 'Reference']][0] AS label, m.name AS name, "
        f"type(r) AS rel, startNode(r) = n AS outgoing, r.description AS evidence, "
        f"{key_expr('n')} AS self_id ORDER BY rel, label, id LIMIT $limit",
        uid=ref.uid, types=types, limit=limit + 1,
    )
    truncated = len(rows) > limit
    neighbors, paths = [], []
    for r in rows[:limit]:
        src, dst = (r["self_id"], r["id"]) if r["outgoing"] else (r["id"], r["self_id"])
        paths.append([src, r["rel"], dst])
        item = {"id": r["id"], "label": r["label"], "name": r["name"], "rel": r["rel"], "direction": "out" if r["outgoing"] else "in"}
        if r["evidence"]:
            item["evidence"] = short(r["evidence"])
        neighbors.append(item)
    return {"id": ref.key, "neighbors": neighbors, "paths": paths, "returned": len(neighbors), "truncated": truncated}


def find_paths(ctx: Context, from_id: str, to_label: str, max_hops: int = MAX_HOPS, limit: int = 25, kev_only: bool = False) -> dict[str, Any]:
    """Distinct nodes of type `to_label` reachable from `from_id`, each with up to two example paths.
    `limit` counts distinct end nodes (one CVE reached by ten routes counts once)."""
    ref = _ref(from_id)
    if to_label not in LABELS:
        raise ToolInputError(f"unknown to_label {to_label!r}; valid labels: {list(LABELS)}")
    _bounded("max_hops", max_hops, 1, MAX_HOPS)
    _bounded("limit", limit, 1, MAX_ENDPOINTS)
    routes = enumerate_metapaths(ref.label, to_label, max_hops)
    out: dict[str, Any] = {"from": ref.key, "from_label": ref.label, "to_label": to_label, "kev_only": kev_only,
                           "routes": [r.describe() for r in routes], "paths": [], "endpoint_count": 0, "truncated": False}
    if not routes:
        out["note"] = f"No schema route from {ref.label} to {to_label} within {max_hops} hops. Try get_neighbors or cypher_query."
        return out
    seen: set[str] = set()
    for route in routes:
        rows = _rows(ctx, metapath_cypher(route, kev_only=kev_only) + " LIMIT $limit", uid=ref.uid, limit=limit + 1, examples=EXAMPLES_PER_ENDPOINT)
        for r in rows:
            if r["end_id"] in seen:
                continue
            if len(seen) >= limit:
                out["truncated"] = True
                break
            seen.add(r["end_id"])
            for ex in r["examples"]:
                out["paths"].append({"route": route.describe(), "hops": route.hops, "nodes": ex["nodes"], "triples": ex["triples"],
                                     "end_path_count": r["path_count"]})
        if out["truncated"]:
            break
    out["endpoint_count"] = len(seen)
    if any(r.weakness_level for r in routes):
        out["note"] = WEAKNESS_NOTE
    return out


def cypher_query(ctx: Context, cypher: str) -> dict[str, Any]:
    result = run_read_ex(ctx.driver, cypher)
    out: dict[str, Any] = {"rows": [jsonable(r) for r in result.rows], "row_count": len(result.rows),
                           "truncated": len(result.rows) >= MAX_ROWS, "executed": result.executed}
    if result.warnings:
        out["warnings"] = [short(w, 200) for w in result.warnings[:3]]  # e.g. an unknown property: probably a typo
    return out


def resolve_entity(ctx: Context, name: str, labels: list[str] | None = None, limit: int = 5) -> dict[str, Any]:
    text = name.strip()
    if not text:
        raise ToolInputError("name is empty")
    _bounded("limit", limit, 1, 20)
    wanted = _check_labels(labels)
    escaped = _LUCENE_SPECIAL.sub(r"\\\1", text)
    words = [w for w in escaped.split() if w]
    queries = [f'"{escaped}"', " AND ".join(f"{w}~" for w in words)]  # exact phrase first, fuzzy as a fallback
    found: dict[str, dict[str, Any]] = {}
    for q in queries:
        rows = _rows(
            ctx,
            "CALL db.index.fulltext.queryNodes('text_search', $q, {limit: $n}) YIELD node, score "
            "RETURN " + key_expr("node") + " AS id, [l IN labels(node) WHERE NOT l IN ['Searchable', 'Reference']][0] AS label, "
            "node.name AS name, coalesce(node.aliases, []) AS aliases, score",
            q=q, n=max(limit * 3, 10),
        )
        for r in rows:
            if wanted is None or r["label"] in wanted:
                found.setdefault(r["id"], r)
        if found:
            break
    low = text.lower()
    candidates = []
    for r in found.values():
        alias = next((a for a in r["aliases"] if a.lower() == low), None)
        exact = (r["name"] or "").lower() == low or alias is not None
        candidates.append({"id": r["id"], "label": r["label"], "name": r["name"], "exact": exact,
                           "matched_alias": alias, "aliases": r["aliases"][:8], "score": round(float(r["score"]), 3)})
    candidates.sort(key=lambda c: (not c["exact"], -c["score"]))
    return {"query": text, "candidates": candidates[:limit]}


MAX_REPORTS = 5
MAX_ASSERTED = 40


def report_insights(ctx: Context, report_id: str | None = None, entity_id: str | None = None) -> dict[str, Any]:
    """What ingested threat reports say, set against curated ATT&CK. For each report and each curated actor, software or
    campaign it mentions: the techniques the report ties to it that ATT&CK already records (`confirmed`) and those it does
    not (`new`). Report claims come from automated extraction and are unverified. Filter by report and/or entity."""
    if report_id is not None and not report_id.strip():
        raise ToolInputError("report_id is empty")
    rows = _rows(
        ctx,
        "MATCH (r:Report)-[m:MENTIONS]->(e) WHERE (e:Group OR e:Software OR e:Campaign) "
        "AND ($rid IS NULL OR r.report_id = $rid) AND ($eid IS NULL OR " + key_expr("e") + " = $eid) "
        "OPTIONAL MATCH (e)-[a:ASSERTED {report_id: r.report_id}]->(t:Technique) "
        "WITH r, e, m, collect(DISTINCT CASE WHEN t IS NULL THEN NULL ELSE {id: t.attack_id, name: t.name, in_attack: EXISTS { (e)-[:USES]->(t) }} END) AS asserted "
        "RETURN r.report_id AS report_id, r.title AS title, r.source AS source, " + key_expr("e") + " AS id, e.name AS name, "
        "[l IN labels(e) WHERE NOT l IN ['Searchable', 'Reference']][0] AS label, m.count AS mentions, asserted "
        "ORDER BY r.ingested_at DESC, mentions DESC LIMIT 200",
        rid=report_id, eid=entity_id,
    )
    reports: dict[str, dict[str, Any]] = {}
    for r in rows:
        if r["report_id"] not in reports and len(reports) >= MAX_REPORTS:
            continue
        slot = reports.setdefault(r["report_id"], {"report_id": r["report_id"], "title": r["title"], "source": r["source"], "entities": []})
        asserted = [a for a in r["asserted"] if a]
        slot["entities"].append({
            "id": r["id"], "name": r["name"], "label": r["label"], "mentions": r["mentions"],
            "confirmed": [{"id": a["id"], "name": a["name"]} for a in asserted if a["in_attack"]][:MAX_ASSERTED],
            "new": [{"id": a["id"], "name": a["name"]} for a in asserted if not a["in_attack"]][:MAX_ASSERTED],
        })
    for rid, slot in reports.items():
        prov = _rows(ctx, "MATCH (:Report {report_id: $rid})-[m:MENTIONS]->(p:ProvisionalEntity) RETURN p.name AS name, p.entity_type AS type ORDER BY m.count DESC LIMIT 15", rid=rid)
        slot["provisional"] = prov
        slot["techniques_asserted"] = _rows(ctx, "MATCH (:Report {report_id: $rid})-[:ASSERTS_TECHNIQUE]->(t:Technique) RETURN count(t) AS n", rid=rid)[0]["n"]
    return {"reports": list(reports.values()), "note": "Report claims are automated extractions and unverified; `new` means ATT&CK does not link that entity to the technique."}


def _graph_cve(ctx: Context, cve_id: str) -> dict[str, Any] | None:
    rows = _rows(
        ctx,
        "MATCH (v:CVE {cve_id: $id}) OPTIONAL MATCH (v)-[h:HAS_WEAKNESS]->(w:CWE) "
        "RETURN properties(v) AS props, collect(CASE WHEN w IS NULL THEN NULL ELSE {id: w.cwe_id, name: w.name, type: h.type} END) AS weaknesses",
        id=cve_id,
    )
    if not rows:
        return None
    props = {k: v for k, v in rows[0]["props"].items() if k not in HIDDEN_PROPS}
    props["description"] = short(props.get("description"), DETAIL_DESCRIPTION_CHARS)
    return {"found": True, "source": "graph", "in_graph": True, "id": cve_id, "properties": props,
            "weaknesses": [w for w in rows[0]["weaknesses"] if w]}


def _live_cve(ctx: Context, cve_id: str) -> dict[str, Any] | None:
    cache = ctx.nvd_cache_dir / f"{cve_id}.json" if ctx.nvd_cache_dir else None
    payload: dict[str, Any] | None = None
    if cache is not None and cache.exists():
        cached = json.loads(cache.read_text())
        if time.time() - cached["fetched_at"] < NVD_TTL_S:
            payload = cached["payload"]
    if payload is None:
        client = ctx.http or httpx.Client(timeout=httpx.Timeout(20.0, connect=10.0))
        wait = NVD_MIN_INTERVAL_S - (time.monotonic() - ctx._last_nvd_call)
        if ctx._last_nvd_call and wait > 0:
            time.sleep(wait)
        ctx._last_nvd_call = time.monotonic()
        try:
            resp = client.get(NVD_URL, params={"cveId": cve_id})
        except httpx.TransportError as exc:
            raise ToolInputError(f"live NVD lookup failed: {type(exc).__name__}") from exc
        if resp.status_code in (403, 429):
            raise ToolInputError("NVD rate limit reached; retry in about 30 seconds")
        if resp.status_code != 200:
            raise ToolInputError(f"live NVD lookup failed: HTTP {resp.status_code}")
        payload = resp.json()
        if cache is not None:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps({"fetched_at": time.time(), "payload": payload}))
    items = payload.get("vulnerabilities") or []
    if not items:
        return None
    from collections import Counter

    cve = items[0]["cve"]
    record = parse_cve(cve, Counter())
    if record is None:
        return {"found": True, "source": "nvd_live", "in_graph": False, "id": cve_id, "properties": {"vuln_status": "Rejected"}, "weaknesses": []}
    return {
        "found": True, "source": "nvd_live", "in_graph": False, "id": cve_id,
        "properties": {**record.node.props, "description": short(record.node.props.get("description"), DETAIL_DESCRIPTION_CHARS),
                       "kev": None},
        "weaknesses": [{"id": w, "type": t} for w, t in record.weaknesses.items()],
        "note": "Fetched live from NVD, not in the graph. KEV status is not checked for live results.",
        "fetched_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }


def cve_lookup(ctx: Context, cve_id: str, live: bool = True) -> dict[str, Any]:
    ref = parse_id(cve_id)
    if ref is None or ref.label != "CVE":
        raise ToolInputError(f"{cve_id!r} is not a CVE identifier (expected CVE-YYYY-NNNN)")
    local = _graph_cve(ctx, ref.key)
    if local is not None:
        return local
    if live and ctx.nvd_live:
        remote = _live_cve(ctx, ref.key)
        if remote is not None:
            return remote
    return {"found": False, "id": ref.key, "in_graph": False, "live_checked": bool(live and ctx.nvd_live)}
