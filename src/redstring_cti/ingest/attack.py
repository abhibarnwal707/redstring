"""MITRE ATT&CK (STIX 2.1) ingester.

`parse_attack` is pure (file -> typed records + skip statistics) so it can be tested
without Neo4j. `load_attack` writes the records with idempotent MERGEs.
"""

import logging
from collections import Counter
from pathlib import Path
from typing import Any

import orjson
from neo4j import Driver
from pydantic import BaseModel

from redstring_cti.graph.loader import write_edges, write_nodes
from redstring_cti.ingest.common import Edge, Node, strip_markup

log = logging.getLogger(__name__)

SOURCE = "mitre-attack"

KEY_PROP = "attack_id"

STIX_TO_LABEL: dict[str, str] = {
    "intrusion-set": "Group",
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "malware": "Software",
    "tool": "Software",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}
STIX_TO_REL: dict[str, str] = {
    "uses": "USES",
    "mitigates": "MITIGATES",
    "subtechnique-of": "SUBTECHNIQUE_OF",
    "attributed-to": "ATTRIBUTED_TO",
}
# (relationship, source label, target label) combinations we accept
ALLOWED_PAIRS: set[tuple[str, str, str]] = {
    ("USES", "Group", "Technique"),
    ("USES", "Software", "Technique"),
    ("USES", "Campaign", "Technique"),
    ("USES", "Group", "Software"),
    ("USES", "Campaign", "Software"),
    ("MITIGATES", "Mitigation", "Technique"),
    ("SUBTECHNIQUE_OF", "Technique", "Technique"),
    ("ATTRIBUTED_TO", "Campaign", "Group"),
}


class AttackGraph(BaseModel):
    version: str
    nodes: list[Node]
    edges: list[Edge]
    stats: dict[str, int]


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == SOURCE:
            ext_id = ref.get("external_id")
            return str(ext_id) if ext_id else None
    return None


def _node_props(obj: dict[str, Any], label: str) -> dict[str, Any]:
    props: dict[str, Any] = {
        "name": obj.get("name"),
        "description": strip_markup(obj.get("description")),
        "stix_id": obj["id"],
    }
    if label == "Group":
        props["aliases"] = obj.get("aliases", [])
    elif label == "Technique":
        props["is_subtechnique"] = bool(obj.get("x_mitre_is_subtechnique", False))
        props["platforms"] = obj.get("x_mitre_platforms", [])
    elif label == "Tactic":
        props["shortname"] = obj.get("x_mitre_shortname")
    elif label == "Software":
        props["type"] = obj["type"]  # malware | tool
        props["aliases"] = obj.get("x_mitre_aliases", [])
    elif label == "Campaign":
        props["aliases"] = obj.get("aliases", [])
        props["first_seen"] = obj.get("first_seen")
        props["last_seen"] = obj.get("last_seen")
    return {k: v for k, v in props.items() if v is not None}


def _edge(rel: str, src: Node, dst: Node, props: dict[str, Any]) -> Edge:
    return Edge(
        rel=rel,
        src_label=src.label,
        src_prop=src.key_prop,
        src_key=src.key,
        dst_label=dst.label,
        dst_prop=dst.key_prop,
        dst_key=dst.key,
        props=props,
    )


def parse_attack(path: Path, version: str) -> AttackGraph:
    objects: list[dict[str, Any]] = orjson.loads(path.read_bytes())["objects"]
    stats: Counter[str] = Counter()

    nodes: list[Node] = []
    by_stix: dict[str, Node] = {}
    raw_by_stix: dict[str, dict[str, Any]] = {}
    for obj in objects:
        label = STIX_TO_LABEL.get(obj["type"])
        if label is None:
            continue
        if obj.get("revoked"):
            stats[f"skipped_revoked:{obj['type']}"] += 1
            continue
        if obj.get("x_mitre_deprecated"):
            stats[f"skipped_deprecated:{obj['type']}"] += 1
            continue
        attack_id = _external_id(obj)
        if attack_id is None:
            stats[f"skipped_no_attack_id:{obj['type']}"] += 1
            continue
        node = Node(label=label, key_prop=KEY_PROP, key=attack_id, props=_node_props(obj, label))
        nodes.append(node)
        by_stix[obj["id"]] = node
        raw_by_stix[obj["id"]] = obj

    edges: list[Edge] = []
    for obj in objects:
        if obj["type"] != "relationship":
            continue
        rel = STIX_TO_REL.get(obj["relationship_type"])
        if rel is None:
            continue
        src, dst = by_stix.get(obj["source_ref"]), by_stix.get(obj["target_ref"])
        if src is None or dst is None:
            stats[f"edges_dropped_endpoint_not_live:{rel}"] += 1
            continue
        if (rel, src.label, dst.label) not in ALLOWED_PAIRS:
            stats[f"edges_dropped_invalid_pair:{rel}:{src.label}->{dst.label}"] += 1
            continue
        description = strip_markup(obj.get("description"))
        edges.append(
            _edge(rel, src, dst, {"description": description} if description else {})
        )

    tactic_by_short = {
        n.props["shortname"]: n for n in nodes if n.label == "Tactic" and "shortname" in n.props
    }
    for stix_id, raw in raw_by_stix.items():
        if by_stix[stix_id].label != "Technique":
            continue
        for phase in raw.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != SOURCE:
                continue
            tactic = tactic_by_short.get(phase["phase_name"])
            if tactic is None:
                stats["in_tactic_unresolved"] += 1
                continue
            tech = by_stix[stix_id]
            edges.append(_edge("IN_TACTIC", tech, tactic, {}))

    for n in nodes:
        stats[f"nodes:{n.label}"] += 1
    for e in edges:
        stats[f"edges:{e.rel}"] += 1
    return AttackGraph(version=version, nodes=nodes, edges=edges, stats=dict(sorted(stats.items())))


def load_attack(driver: Driver, graph: AttackGraph) -> None:
    write_nodes(driver, graph.nodes, source=SOURCE, version=graph.version)
    write_edges(driver, graph.edges, source=SOURCE)
    skipped = {
        k: v for k, v in graph.stats.items() if k.startswith(("skipped", "edges_dropped", "in_tactic"))
    }
    log.info("skipped/dropped: %s", skipped)
