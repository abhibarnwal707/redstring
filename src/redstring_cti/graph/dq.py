"""Data-quality report (`make dq`): what is in the graph, what was skipped, and how well the
sources connect. Writes evals/results/data_quality.md.

Graph numbers come from the live Neo4j graph; skip counts are recomputed from the raw files so
the report does not depend on a log from an earlier run.
"""

import argparse
import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import ijson
import orjson
from neo4j import Driver

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.graph.loader import existing_keys, get_driver
from redstring_cti.ingest.attack import parse_attack
from redstring_cti.ingest.capec import parse_capec
from redstring_cti.ingest.cwe import parse_cwe
from redstring_cti.ingest.nvd import feed_paths, iter_cves

log = logging.getLogger(__name__)

OUT_PATH = Path(__file__).resolve().parents[3] / "evals" / "results" / "data_quality.md"
HELPER_LABELS = {"Reference", "Searchable"}
CHAIN = "(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)<-[:HAS_WEAKNESS]-"


def pct(part: int, whole: int) -> str:
    return f"{100 * part / whole:.1f}%" if whole else "n/a"


def fraction(part: int, whole: int) -> str:
    return f"{part:,} of {whole:,} ({pct(part, whole)})"


def table(headers: list[str], rows: list[list[Any]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(f"{c:,}" if isinstance(c, int) else str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def one(session: Any, cypher: str, **params: Any) -> dict[str, Any]:
    record = session.run(cypher, **params).single()
    return dict(record) if record else {}


# ------------------------------------------------------------------ graph metrics
def graph_metrics(driver: Driver) -> dict[str, Any]:
    m: dict[str, Any] = {}
    with driver.session() as s:
        m["nodes"] = {
            r["l"]: r["c"]
            for r in s.run("MATCH (n) UNWIND labels(n) AS l WITH l, count(*) AS c RETURN l, c ORDER BY c DESC")
            if r["l"] not in HELPER_LABELS
        }
        m["edges"] = {r["t"]: r["c"] for r in s.run("MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c ORDER BY c DESC")}
        m["orphans"] = {
            label: one(s, f"MATCH (n:{label}) WHERE NOT (n)--() RETURN count(n) AS c")["c"] for label in m["nodes"]
        }

        m["tech"] = one(
            s,
            """MATCH (t:Technique)
               RETURN count(t) AS total,
                      sum(CASE WHEN EXISTS { (t)<-[:MAPS_TO]-() } THEN 1 ELSE 0 END) AS mapped,
                      sum(CASE WHEN t.is_subtechnique THEN 1 ELSE 0 END) AS subs,
                      sum(CASE WHEN t.is_subtechnique AND EXISTS { (t)<-[:MAPS_TO]-() } THEN 1 ELSE 0 END) AS subs_mapped""",
        )
        m["capec"] = one(
            s,
            """MATCH (c:CAPEC)
               RETURN count(c) AS total,
                      sum(CASE WHEN EXISTS { (c)-[:MAPS_TO]->() } THEN 1 ELSE 0 END) AS to_technique,
                      sum(CASE WHEN EXISTS { (c)-[:EXPLOITS]->() } THEN 1 ELSE 0 END) AS to_cwe""",
        )
        m["cve"] = one(
            s,
            f"""MATCH (v:CVE)
               RETURN count(v) AS total,
                      sum(CASE WHEN EXISTS {{ (v)-[:HAS_WEAKNESS]->() }} THEN 1 ELSE 0 END) AS with_cwe,
                      sum(CASE WHEN v.kev THEN 1 ELSE 0 END) AS kev,
                      sum(CASE WHEN v.kev AND EXISTS {{ (v)-[:HAS_WEAKNESS]->() }} THEN 1 ELSE 0 END) AS kev_with_cwe,
                      sum(CASE WHEN EXISTS {{ MATCH {CHAIN}(v) }} THEN 1 ELSE 0 END) AS on_chain,
                      sum(CASE WHEN v.kev AND EXISTS {{ MATCH {CHAIN}(v) }} THEN 1 ELSE 0 END) AS kev_on_chain,
                      sum(CASE WHEN v.cvss_score IS NULL THEN 1 ELSE 0 END) AS no_cvss""",
        )
        m["cvss_versions"] = {
            str(r["v"]): r["c"]
            for r in s.run("MATCH (v:CVE) RETURN v.cvss_version AS v, count(*) AS c ORDER BY c DESC")
        }
        m["groups"] = one(
            s,
            f"""MATCH (g:Group)
               RETURN count(g) AS total,
                      sum(CASE WHEN EXISTS {{ (g)-[:USES]->(:Technique) }} THEN 1 ELSE 0 END) AS with_technique,
                      sum(CASE WHEN EXISTS {{ (g)-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC) }} THEN 1 ELSE 0 END) AS to_capec,
                      sum(CASE WHEN EXISTS {{ (g)-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE) }} THEN 1 ELSE 0 END) AS to_cwe,
                      sum(CASE WHEN EXISTS {{ MATCH (g)-[:USES]->{CHAIN}(:CVE) }} THEN 1 ELSE 0 END) AS to_cve,
                      sum(CASE WHEN EXISTS {{ MATCH (g)-[:USES]->{CHAIN}(:CVE {{kev: true}}) }} THEN 1 ELSE 0 END) AS to_kev""",
        )
        m["uses_edges"] = one(
            s,
            """MATCH (:Group)-[u:USES]->(t:Technique)
               RETURN count(u) AS total,
                      sum(CASE WHEN EXISTS { (t)<-[:MAPS_TO]-() } THEN 1 ELSE 0 END) AS to_mapped_technique""",
        )
        m["chain_by_abstraction"] = {
            str(r["a"]): r["c"]
            for r in s.run(
                """MATCH (v:CVE)-[:HAS_WEAKNESS]->(w:CWE)<-[:EXPLOITS]-(:CAPEC)-[:MAPS_TO]->(:Technique)
                    RETURN w.abstraction AS a, count(DISTINCT v) AS c ORDER BY c DESC"""
            )
        }
        m["top_chain_cwes"] = [
            dict(r)
            for r in s.run(
                """MATCH (v:CVE)-[:HAS_WEAKNESS]->(w:CWE)<-[:EXPLOITS]-(:CAPEC)-[:MAPS_TO]->(:Technique)
                   RETURN w.cwe_id AS cwe, w.name AS name, w.abstraction AS abstraction, count(DISTINCT v) AS cves
                   ORDER BY cves DESC LIMIT 8"""
            )
        ]
        m["embeddings"] = {
            r["l"]: (r["with_vec"], r["total"])
            for r in s.run(
                """MATCH (n:Searchable)
                   RETURN [l IN labels(n) WHERE l <> 'Searchable' AND l <> 'Reference'][0] AS l, count(*) AS total,
                          sum(CASE WHEN n.embedding IS NOT NULL THEN 1 ELSE 0 END) AS with_vec"""
            )
        }
        m["apt29"] = one(
            s,
            """MATCH (:Group {attack_id: 'G0016'})-[:USES]->(t:Technique)
               RETURN count(DISTINCT t) AS techniques,
                      count(DISTINCT CASE WHEN EXISTS { (t)<-[:MAPS_TO]-() } THEN t END) AS with_capec""",
        )
    return m


# ------------------------------------------------------------------ raw-file metrics
def source_metrics(driver: Driver, raw_dir: Path) -> dict[str, Any]:
    m: dict[str, Any] = {}
    attack = parse_attack(raw_dir / f"enterprise-attack-{ATTACK_VERSION}.json", ATTACK_VERSION)
    m["attack_skips"] = {k: v for k, v in attack.stats.items() if k.startswith(("skipped", "edges_dropped", "in_tactic"))}
    cwe = parse_cwe(raw_dir / "cwec_latest.xml.zip")
    m["cwe_version"] = cwe.version
    m["cwe_skips"] = {k: v for k, v in cwe.stats.items() if k.startswith(("skipped", "edges_dropped"))}
    capec = parse_capec(raw_dir / "capec_latest.xml")
    m["capec_version"] = capec.version
    m["capec_skips"] = {k: v for k, v in capec.stats.items() if k.startswith(("skipped", "edges_dropped"))}
    techniques = existing_keys(driver, "Technique", "attack_id")
    maps = [e for e in capec.edges if e.rel == "MAPS_TO"]
    m["maps_to_parsed"] = len(maps)
    m["maps_to_dropped"] = sum(1 for e in maps if e.dst_key not in techniques)

    cwe_ids = existing_keys(driver, "CWE", "cwe_id")
    state: dict[str, str] = {}  # final classification per CVE id (modified feed is read last and wins)
    rejected: set[str] = set()
    unmatched: Counter[str] = Counter()
    seen_records = 0
    for path in feed_paths(raw_dir):
        for rec in iter_cves(path, Counter(), rejected):
            seen_records += 1
            real = rec.weaknesses
            if real:
                state[rec.node.key] = "matched" if any(c in cwe_ids for c in real) else "real_cwe_not_in_graph"
            else:
                state[rec.node.key] = "pseudo_only" if rec.pseudo_weakness else "no_weakness_data"
            for cwe_id in real:
                if cwe_id not in cwe_ids:
                    unmatched[cwe_id] += 1
    still_rejected = rejected - set(state)
    m["nvd"] = {
        "feeds": len(feed_paths(raw_dir)),
        "records": seen_records,
        "distinct_live": len(state),
        "distinct_rejected": len(still_rejected),
        "classes": dict(Counter(state.values())),
        "unmatched_distinct": len(unmatched),
        "unmatched_refs": sum(unmatched.values()),
        "unmatched_top": unmatched.most_common(5),
    }
    kev_path = raw_dir / "known_exploited_vulnerabilities.json"
    kev = orjson.loads(kev_path.read_bytes())
    m["kev"] = {"version": kev.get("catalogVersion"), "count": kev.get("count")}
    modified = raw_dir / "nvdcve-2.0-modified.json.gz"
    ts = None
    if modified.exists():
        import gzip

        with gzip.open(modified, "rb") as f:
            for prefix, event, value in ijson.parse(f):
                if (prefix, event) == ("timestamp", "string"):
                    ts = value
                    break
    m["nvd_timestamp"] = ts
    return m


def collect(driver: Driver, raw_dir: Path = RAW_DIR) -> dict[str, Any]:
    return {"graph": graph_metrics(driver), "source": source_metrics(driver, raw_dir)}


# ------------------------------------------------------------------ rendering
def render(metrics: dict[str, Any], generated: datetime | None = None) -> str:
    g, src = metrics["graph"], metrics["source"]
    t, c, v, grp = g["tech"], g["capec"], g["cve"], g["groups"]
    nvd = src["nvd"]
    when = (generated or datetime.now(UTC)).strftime("%Y-%m-%d %H:%M UTC")
    classes = nvd["classes"]

    parts = [
        "# Data-quality report",
        f"Generated {when} by `make dq` from the live graph and the raw files in `data/raw/`.",
        "",
        "## 1. Sources and versions",
        table(
            ["Source", "Version / snapshot"],
            [
                ["MITRE ATT&CK Enterprise", ATTACK_VERSION],
                ["CWE", src["cwe_version"]],
                ["CAPEC", src["capec_version"]],
                ["NVD CVE JSON 2.0", f"{nvd['feeds']} feeds (yearly + modified); modified-feed snapshot {src['nvd_timestamp']}"],
                ["CISA KEV", f"catalog {src['kev']['version']}, {src['kev']['count']:,} entries"],
            ],
        ),
        "",
        "## 2. What is in the graph",
        "**Nodes**",
        "",
        table(["Label", "Count"], [[k, n] for k, n in g["nodes"].items()]),
        "",
        "**Edges**",
        "",
        table(["Relationship", "Count"], [[k, n] for k, n in g["edges"].items()]),
        "",
        f"Total: {sum(g['nodes'].values()):,} nodes, {sum(g['edges'].values()):,} edges.",
        "",
        "## 3. Skipped or dropped during ingestion",
        "",
        "Revoked or deprecated objects are removed on purpose; counts are recomputed from the raw files.",
        "",
        table(
            ["Source", "Item", "Count"],
            [
                *[["ATT&CK", k, n] for k, n in src["attack_skips"].items()],
                *[["CWE", k, n] for k, n in src["cwe_skips"].items()],
                *[["CAPEC", k, n] for k, n in src["capec_skips"].items()],
                ["CAPEC", "ATT&CK mappings parsed", src["maps_to_parsed"]],
                ["CAPEC", "mappings dropped (technique revoked or deprecated)", src["maps_to_dropped"]],
                ["NVD", "records read across all feeds (modified overlaps yearly)", nvd["records"]],
                ["NVD", "CVEs kept (distinct)", nvd["distinct_live"]],
                ["NVD", "CVEs skipped as Rejected (distinct)", nvd["distinct_rejected"]],
                ["NVD", "CWE ids referenced by CVEs but absent from the graph (distinct)", nvd["unmatched_distinct"]],
                ["NVD", "CVE-to-CWE references dropped for that reason", nvd["unmatched_refs"]],
            ],
        ),
        "",
        "## 4. Orphans (nodes with no relationships)",
        "",
        table(
            ["Label", "Orphans", "Of"],
            [[k, g["orphans"][k], g["nodes"][k]] for k in g["nodes"] if g["orphans"][k]]
            or [["none", 0, 0]],
        ),
        "",
        "A CVE with no relationships is one with no usable CWE (see section 5). Labels not listed have no orphans.",
        "",
        "## 5. Coverage: how well the sources connect",
        "",
        "### CAPEC to ATT&CK (the bridge between attacker behaviour and weaknesses)",
        "",
        table(
            ["Measure", "Value"],
            [
                ["Techniques with at least one CAPEC mapping", fraction(t["mapped"], t["total"])],
                ["...top-level techniques", fraction(t["mapped"] - t["subs_mapped"], t["total"] - t["subs"])],
                ["...sub-techniques", fraction(t["subs_mapped"], t["subs"])],
                ["CAPEC patterns mapped to at least one technique", fraction(c["to_technique"], c["total"])],
                ["CAPEC patterns linked to at least one CWE", fraction(c["to_cwe"], c["total"])],
                ["Group-to-technique edges whose technique has a CAPEC mapping", fraction(g["uses_edges"]["to_mapped_technique"], g["uses_edges"]["total"])],
                ["APT29 techniques with a CAPEC mapping", fraction(g["apt29"]["with_capec"], g["apt29"]["techniques"])],
            ],
        ),
        "",
        "ATT&CK v20 techniques carry no CAPEC references of their own, so every `MAPS_TO` edge comes from CAPEC's taxonomy mappings.",
        "",
        "### CVE to CWE",
        "",
        table(
            ["Measure", "Value"],
            [
                ["CVEs with a `HAS_WEAKNESS` edge", fraction(v["with_cwe"], v["total"])],
                ["KEV CVEs with a `HAS_WEAKNESS` edge", fraction(v["kev_with_cwe"], v["kev"])],
                ["CVEs listing only pseudo-weaknesses (NVD-CWE-Other / noinfo)", fraction(classes.get("pseudo_only", 0), nvd["distinct_live"])],
                ["CVEs with no weakness data at all", fraction(classes.get("no_weakness_data", 0), nvd["distinct_live"])],
                ["CVEs whose only CWEs are missing from our graph", fraction(classes.get("real_cwe_not_in_graph", 0), nvd["distinct_live"])],
                ["CVEs without any CVSS score", fraction(v["no_cvss"], v["total"])],
            ],
        ),
        "",
        "CVSS version used: " + ", ".join(f"{k}: {n:,}" for k, n in g["cvss_versions"].items()) + ".",
        "",
        "Most frequent CWE ids referenced by CVEs but absent from the graph: "
        + (", ".join(f"{k} ({n:,})" for k, n in src["nvd"]["unmatched_top"]) or "none")
        + ".",
        "",
        ("These are CWE *categories* (legacy groupings such as CWE-264 \"Permissions, Privileges, and Access Controls\"), "
        "not weaknesses; checked against CWE 4.20 for the ids above. The CWE ingester loads weaknesses only, so these "
        "references are dropped. Loading categories would recover those CVE links but would add nodes no CAPEC pattern "
        "points to, so it is left as an open decision."),
        "",
        "### Full chain: Group, Technique, CAPEC, CWE, CVE",
        "",
        table(
            ["Measure", "Value"],
            [
                ["Groups using at least one technique", fraction(grp["with_technique"], grp["total"])],
                ["...that reach a CAPEC pattern", fraction(grp["to_capec"], grp["total"])],
                ["...that reach a CWE", fraction(grp["to_cwe"], grp["total"])],
                ["...that reach at least one CVE through the full chain", fraction(grp["to_cve"], grp["total"])],
                ["...that reach at least one KEV CVE through the full chain", fraction(grp["to_kev"], grp["total"])],
                ["CVEs reachable from some technique through the chain", fraction(v["on_chain"], v["total"])],
                ["KEV CVEs reachable through the chain", fraction(v["kev_on_chain"], v["kev"])],
            ],
        ),
        "",
        ("**How specific are the chain links?** The weakness a chain passes through decides how meaningful it is. "
        "A CVE with several weaknesses is counted once per abstraction level, so the rows add up to more than the total above."),
        "",
        table(
            ["CWE abstraction level", "CVEs reached through it"],
            [[k, n] for k, n in g["chain_by_abstraction"].items()],
        ),
        "",
        "Weaknesses most often on the chain:",
        "",
        table(
            ["CWE", "Name", "Abstraction", "CVEs"],
            [[r["cwe"], str(r["name"])[:70], r["abstraction"], r["cves"]] for r in g["top_chain_cwes"]],
        ),
        "",
        "## 6. Embedding coverage",
        "",
        table(
            ["Label", "With vector", "Total"],
            [[k, a, b] for k, (a, b) in sorted(g["embeddings"].items(), key=lambda kv: -kv[1][1])],
        ),
        "",
        "Every concept node is embedded. CVEs are embedded only when they are KEV or on the chain above; the rest are found through the full-text index or by ID.",
        "",
        "## 7. What this means for multi-hop answers",
        "",
        f"- **The chain is sparse at its bridge.** Only {pct(t['mapped'], t['total'])} of techniques have a CAPEC mapping, so a question that needs Technique to CAPEC can be answered for only that share of techniques. This is a property of the sources, not a bug.",
        f"- **Most CVEs sit off the chain.** {fraction(v['on_chain'], v['total'])} are reachable from a technique; the remainder have no CWE, a CWE no mapped CAPEC pattern exploits, or only a pseudo-weakness.",
        "- **Chain links are weakness-level, not observed exploitation.** A group reaching a CVE means the group uses a technique that a CAPEC pattern ties to a weakness that CVE also has. Answers must say so, and must not claim the group used that CVE.",
        "- **Generic weaknesses inflate the chain.** The abstraction table shows how many CVEs are reached only through broad Class/Pillar weaknesses; those links are the weakest.",
        "- **Direct evidence lives in text.** Statements such as \"APT29 exploited CVE-2019-19781\" appear in `USES` descriptions and threat reports, which is the job of the fine-tuned extractor.",
        "",
    ]
    return "\n".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the data-quality report.")
    parser.add_argument("--out", type=Path, default=OUT_PATH)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    driver = get_driver()
    try:
        report = render(collect(driver))
    finally:
        driver.close()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report)
    log.info("wrote %s (%d lines)", args.out, report.count("\n"))


if __name__ == "__main__":
    main()
