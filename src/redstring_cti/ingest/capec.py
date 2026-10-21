"""CAPEC ingester: attack patterns, their hierarchy, CWE links and ATT&CK technique mappings.

CAPEC is the bridge between ATT&CK (techniques) and CWE (weaknesses). It writes ATT&CK
ids without the `T` prefix (`1574.010`), so they are normalised to `T1574.010`.
"""

import logging
from collections import Counter
from pathlib import Path
from xml.etree import ElementTree as ET

from neo4j import Driver
from pydantic import BaseModel

from redstring_cti.graph.loader import existing_keys, write_edges, write_nodes
from redstring_cti.ingest.common import Edge, Node
from redstring_cti.ingest.cwe import child, local, open_xml, text_of

log = logging.getLogger(__name__)

SOURCE = "capec"
KEY_PROP = "capec_id"
SKIP_STATUS = {"Deprecated", "Obsolete"}


class CapecGraph(BaseModel):
    version: str
    nodes: list[Node]
    edges: list[Edge]  # CHILD_OF (CAPEC->CAPEC), EXPLOITS (->CWE), MAPS_TO (->Technique)
    stats: dict[str, int]


def normalise_technique_id(entry_id: str) -> str:
    entry_id = entry_id.strip()
    return entry_id if entry_id.startswith("T") else f"T{entry_id}"


def _edge(rel: str, src: str, dst_label: str, dst_prop: str, dst: str) -> Edge:
    return Edge(
        rel=rel,
        src_label="CAPEC",
        src_prop=KEY_PROP,
        src_key=src,
        dst_label=dst_label,
        dst_prop=dst_prop,
        dst_key=dst,
        props={"via": ["capec"]} if rel == "MAPS_TO" else {},
    )


def parse_capec(path: Path) -> CapecGraph:
    stats: Counter[str] = Counter()
    nodes: dict[str, Node] = {}
    child_of: set[tuple[str, str]] = set()
    exploits: set[tuple[str, str]] = set()
    maps_to: set[tuple[str, str]] = set()
    version = "unknown"

    with open_xml(path) as f:
        for event, elem in ET.iterparse(f, events=("start", "end")):
            name = local(elem.tag)
            if event == "start":
                if name == "Attack_Pattern_Catalog":
                    version = elem.attrib.get("Version", version)
                continue
            if name != "Attack_Pattern":
                continue
            capec_id = f"CAPEC-{elem.attrib['ID']}"
            status = elem.attrib.get("Status", "")
            if status in SKIP_STATUS:
                stats[f"skipped_{status.lower()}:Attack_Pattern"] += 1
                elem.clear()
                continue
            props = {
                "name": elem.attrib.get("Name"),
                "description": text_of(child(elem, "Description")),
                "likelihood": text_of(child(elem, "Likelihood_Of_Attack")),
                "severity": text_of(child(elem, "Typical_Severity")),
                "status": status or None,
            }
            nodes[capec_id] = Node(
                label="CAPEC",
                key_prop=KEY_PROP,
                key=capec_id,
                props={k: v for k, v in props.items() if v is not None},
            )
            for sub in elem.iter():
                sub_name = local(sub.tag)
                if sub_name == "Related_Attack_Pattern" and sub.attrib.get("Nature") == "ChildOf":
                    child_of.add((capec_id, f"CAPEC-{sub.attrib['CAPEC_ID']}"))
                elif sub_name == "Related_Weakness":
                    exploits.add((capec_id, f"CWE-{sub.attrib['CWE_ID']}"))
                elif sub_name == "Taxonomy_Mapping" and sub.attrib.get("Taxonomy_Name") == "ATTACK":
                    entry = child(sub, "Entry_ID")
                    if entry is not None and entry.text:
                        maps_to.add((capec_id, normalise_technique_id(entry.text)))
            elem.clear()

    edges: list[Edge] = []
    for src, dst in sorted(child_of):
        if dst in nodes:
            edges.append(_edge("CHILD_OF", src, "CAPEC", KEY_PROP, dst))
        else:
            stats["edges_dropped_endpoint_not_kept:CHILD_OF"] += 1
    edges += [_edge("EXPLOITS", s, "CWE", "cwe_id", d) for s, d in sorted(exploits)]
    edges += [_edge("MAPS_TO", s, "Technique", "attack_id", d) for s, d in sorted(maps_to)]

    stats["nodes:CAPEC"] = len(nodes)
    for e in edges:
        stats[f"edges_parsed:{e.rel}"] += 1
    return CapecGraph(
        version=version, nodes=list(nodes.values()), edges=edges, stats=dict(sorted(stats.items()))
    )


def resolve_edges(driver: Driver, graph: CapecGraph) -> tuple[list[Edge], dict[str, int]]:
    """Keep only edges whose CWE / Technique endpoint exists in the graph; count the rest."""
    known = {
        "CWE": existing_keys(driver, "CWE", "cwe_id"),
        "Technique": existing_keys(driver, "Technique", "attack_id"),
    }
    kept: list[Edge] = []
    dropped: Counter[str] = Counter()
    for e in graph.edges:
        if e.dst_label in known and e.dst_key not in known[e.dst_label]:
            dropped[f"edges_dropped_endpoint_missing:{e.rel}"] += 1
            continue
        kept.append(e)
    return kept, dict(sorted(dropped.items()))


def load_capec(driver: Driver, graph: CapecGraph) -> dict[str, int]:
    """Load CAPEC nodes and edges. Load ATT&CK and CWE first. Returns drop statistics."""
    write_nodes(driver, graph.nodes, source=SOURCE, version=graph.version)
    edges, dropped = resolve_edges(driver, graph)
    write_edges(driver, edges, source=SOURCE)
    log.info("capec skipped/dropped: %s", {**dropped, **{k: v for k, v in graph.stats.items() if "skipped" in k}})
    return dropped
