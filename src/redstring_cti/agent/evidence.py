"""Turn raw tool results into compact evidence text.

`ids` of each Evidence are computed from the text the answering model will actually see, so the
citation check can never allow an ID the model was not shown."""

import json
from typing import Any

from redstring_cti.agent.state import Evidence
from redstring_cti.scoring import extract_ids

NEIGHBOR_CAP = 80
PATH_ENDPOINT_CAP = 70
ROW_CAP = 60
CELL_CHARS = 120


def make(tool: str, args: dict[str, Any], text: str, triples: list[list[str]] | None = None, items: int = 0) -> Evidence:
    return {"tool": tool, "args": args, "text": text, "ids": extract_ids(text), "triples": triples or [], "items": items}


def neighbors(res: dict[str, Any], args: dict[str, Any], target_label: str | None) -> Evidence:
    """Group neighbours by (relationship, direction); names included, target-type filter applied."""
    me = res["id"]
    groups: dict[tuple[str, str], list[str]] = {}
    triples: list[list[str]] = []
    shown = 0
    for n, path in zip(res["neighbors"], res["paths"], strict=True):
        if target_label and n["label"] != target_label:
            continue
        if shown >= NEIGHBOR_CAP:
            break
        groups.setdefault((n["rel"], n["direction"]), []).append(f"{n['id']} {n['name'] or ''}".strip())
        triples.append(path)
        shown += 1
    lines = []
    for (rel, direction), members in sorted(groups.items()):
        arrow = f"{me} -{rel}-> " if direction == "out" else f"-{rel}-> {me} from "
        lines.append(f"{arrow}{len(members)} {target_label or 'node'}(s): " + "; ".join(members))
    if res.get("truncated") or shown >= NEIGHBOR_CAP:
        lines.append("(more neighbours exist but are not shown)")
    text = "\n".join(lines) if lines else f"{me} has no {target_label or ''} neighbours in the graph."
    return make("get_neighbors", args, text, triples, shown)


def paths(res: dict[str, Any], args: dict[str, Any]) -> Evidence:
    """One line per distinct end node, saying what was found and (for multi-hop routes) which nodes lead to it."""
    by_end: dict[str, dict[str, Any]] = {}
    triples: list[list[str]] = []
    for p in res["paths"]:
        end = p["nodes"][-1]
        slot = by_end.setdefault(end["id"], {"name": end.get("name"), "via": []})
        for node in p["nodes"][1:-1]:
            if node["id"] not in slot["via"]:
                slot["via"].append(node["id"])
        triples.extend(p["triples"])
    n = res.get("endpoint_count", len(by_end))
    kev = " (restricted to CISA KEV, i.e. actively exploited, CVEs)" if res.get("kev_only") and res["to_label"] == "CVE" else ""
    head = f"{n} distinct {res['to_label']} result(s) reachable from {res['from_label']} {res['from']}{kev}."
    if res["routes"]:
        head += " Route: " + " | ".join(res["routes"]) + "."
    lines = [f"{eid}{' ' + v['name'] if v['name'] else ''}{' (via ' + ', '.join(v['via']) + ')' if v['via'] else ''}" for eid, v in list(by_end.items())[:PATH_ENDPOINT_CAP]]
    tail = []
    if res.get("note"):
        tail.append(f"Note: {res['note']}")
    if res.get("truncated") or n > PATH_ENDPOINT_CAP:
        tail.append("(more results exist but are not shown)")
    if not by_end:
        return make("find_paths", args, f"No {res['to_label']} reachable from {res['from']} over the schema routes. " + (res.get("note") or ""), triples, 0)
    return make("find_paths", args, "\n".join([head, *lines, *tail]), triples, len(by_end))


def entity(res: dict[str, Any], args: dict[str, Any]) -> Evidence:
    if not res.get("found"):
        return make("get_entity", args, f"{res['id']} ({res['label']}) does not exist in the graph.", items=0)
    p = res["properties"]
    keys = ("cvss_score", "cvss_severity", "kev", "kev_date_added", "known_ransomware_use", "published", "abstraction", "likelihood", "severity", "shortname", "is_subtechnique")
    facts = ", ".join(f"{k}={p[k]}" for k in keys if k in p)
    aliases = f"; aliases: {', '.join(p['aliases'][:8])}" if p.get("aliases") else ""
    rel = res.get("relationship_counts", {})
    counts = "; ".join(f"{d}: " + ", ".join(f"{k}={v}" for k, v in c.items()) for d, c in rel.items() if c)
    desc = (p.get("description") or "")[:300]
    text = f"{res['id']} {res['label']} {p.get('name', '')}{aliases}{'; ' + facts if facts else ''}\n{desc}\nRelationship counts - {counts}"
    return make("get_entity", args, text.strip(), items=1)


def rows(res: dict[str, Any], args: dict[str, Any]) -> Evidence:
    shown = res["rows"][:ROW_CAP]
    lines = [json.dumps({k: (str(v)[:CELL_CHARS] if isinstance(v, str) else v) for k, v in r.items()}, default=str) for r in shown]
    extra = f"\n... {res['row_count'] - len(shown)} more rows not shown" if res["row_count"] > len(shown) else ""
    body = "\n".join(lines) + extra if lines else "(the query returned no rows)"
    query = " ".join(str(args.get("cypher", "")).split())
    # Show the query: its conditions (group, KEV, ransomware, thresholds...) are what make the rows the answer.
    text = (
        f"A database query was written to answer this question; its {res['row_count']} result row(s) are the answer.\n"
        f"Query: {query}\nRows:\n{body}"
    )
    return make("cypher_query", args, text, items=res["row_count"])


def search(res: dict[str, Any], args: dict[str, Any]) -> Evidence:
    lines = [f"{h['id']} {h['label']} {h['name'] or ''}: {(h['description'] or '')[:140]} (score {h['score']})".replace("  ", " ") for h in res["results"]]
    return make("semantic_search", args, "Semantic search hits:\n" + "\n".join(lines) if lines else "No semantic matches.", items=len(lines))


def cve(res: dict[str, Any], args: dict[str, Any]) -> Evidence:
    if not res.get("found"):
        return make("cve_lookup", args, f"{res['id']} was not found in the graph or in NVD.", items=0)
    p = res["properties"]
    facts = ", ".join(f"{k}={p[k]}" for k in ("cvss_score", "cvss_severity", "cvss_version", "kev", "kev_date_added", "known_ransomware_use", "published", "vuln_status") if p.get(k) is not None)
    weak = ", ".join(f"{w['id']} ({w.get('type', '')})".replace(" ()", "") for w in res.get("weaknesses", []))
    note = f"\n{res['note']}" if res.get("note") else ""
    text = f"{res['id']} [{res['source']}]: {facts}\n{(p.get('description') or '')[:300]}\nWeaknesses: {weak or 'none listed'}{note}"
    return make("cve_lookup", args, text, items=1)


def note(text: str) -> Evidence:
    return make("note", {}, text, items=0)


def render(evidence: list[Evidence], max_chars: int) -> tuple[str, list[str]]:
    """The evidence block shown to the answering model, plus the IDs visible in it."""
    if not evidence:
        return "(no evidence was retrieved)", []
    budget = max(max_chars // len(evidence), 600)
    parts = []
    for e in evidence:
        text = e["text"] if len(e["text"]) <= budget else e["text"][: budget - 40].rsplit("\n", 1)[0] + "\n(evidence truncated)"
        parts.append(f"[{e['tool']}]\n{text}")
    block = "\n\n".join(parts)
    return block, extract_ids(block)
