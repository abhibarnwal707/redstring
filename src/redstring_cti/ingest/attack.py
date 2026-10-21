"""MITRE ATT&CK (STIX 2.1) ingester.

`parse_attack` is pure (file -> typed records + skip statistics) so it can be tested
without Neo4j. `load_attack` writes the records with idempotent MERGEs.
"""

import logging
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import orjson
from neo4j import Driver
from pydantic import BaseModel, Field

from redstring_cti.graph.loader import write_batches
from redstring_cti.ingest.common import strip_markup

log = logging.getLogger(__name__)

SOURCE = "mitre-attack"

Label = Literal["Group", "Technique", "Tactic", "Software", "Mitigation", "Campaign"]
Rel = Literal["USES", "MITIGATES", "SUBTECHNIQUE_OF", "ATTRIBUTED_TO", "IN_TACTIC"]

STIX_TO_LABEL: dict[str, Label] = {
    "intrusion-set": "Group",
    "attack-pattern": "Technique",
    "x-mitre-tactic": "Tactic",
    "malware": "Software",
    "tool": "Software",
    "course-of-action": "Mitigation",
    "campaign": "Campaign",
}
STIX_TO_REL: dict[str, Rel] = {
    "uses": "USES",
    "mitigates": "MITIGATES",
    "subtechnique-of": "SUBTECHNIQUE_OF",
    "attributed-to": "ATTRIBUTED_TO",
}
# (relationship, source label, target label) combinations we accept
ALLOWED_PAIRS: set[tuple[Rel, Label, Label]] = {
    ("USES", "Group", "Technique"),
    ("USES", "Software", "Technique"),
    ("USES", "Campaign", "Technique"),
    ("USES", "Group", "Software"),
    ("USES", "Campaign", "Software"),
    ("MITIGATES", "Mitigation", "Technique"),
    ("SUBTECHNIQUE_OF", "Technique", "Technique"),
    ("ATTRIBUTED_TO", "Campaign", "Group"),
}


class Node(BaseModel):
    label: Label
    key: str  # ATT&CK id, e.g. T1566.001
    props: dict[str, Any]

    @property
    def uid(self) -> str:
        return f"{self.label}:{self.key}"


class Edge(BaseModel):
    rel: Rel
    src_label: Label
    src_key: str
    dst_label: Label
    dst_key: str
    props: dict[str, Any] = Field(default_factory=dict)


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


def _node_props(obj: dict[str, Any], label: Label) -> dict[str, Any]:
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
        node = Node(label=label, key=attack_id, props=_node_props(obj, label))
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
            Edge(
                rel=rel,
                src_label=src.label,
                src_key=src.key,
                dst_label=dst.label,
                dst_key=dst.key,
                props={"description": description} if description else {},
            )
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
            edges.append(
                Edge(
                    rel="IN_TACTIC",
                    src_label="Technique",
                    src_key=tech.key,
                    dst_label="Tactic",
                    dst_key=tactic.key,
                )
            )

    for n in nodes:
        stats[f"nodes:{n.label}"] += 1
    for e in edges:
        stats[f"edges:{e.rel}"] += 1
    return AttackGraph(version=version, nodes=nodes, edges=edges, stats=dict(sorted(stats.items())))


# Labels and relationship names come from the Literal constants above, never from data.
_NODE_QUERY = """
UNWIND $rows AS row
MERGE (n:{label} {{attack_id: row.key}})
SET n += row.props, n:Searchable, n.uid = row.uid,
    n.source = $source, n.source_version = $version, n.ingested_at = $ingested_at
"""
_EDGE_QUERY = """
UNWIND $rows AS row
MATCH (a:{src} {{attack_id: row.src}})
MATCH (b:{dst} {{attack_id: row.dst}})
MERGE (a)-[r:{rel}]->(b)
SET r += row.props, r.source = $source
"""


def load_attack(driver: Driver, graph: AttackGraph) -> None:
    ingested_at = datetime.now(UTC).isoformat(timespec="seconds")

    by_label: dict[Label, list[dict[str, Any]]] = {}
    for n in graph.nodes:
        by_label.setdefault(n.label, []).append({"key": n.key, "uid": n.uid, "props": n.props})
    for label, rows in by_label.items():
        write_batches(
            driver,
            _NODE_QUERY.format(label=label),
            rows,
            source=SOURCE,
            version=graph.version,
            ingested_at=ingested_at,
        )
        log.info("loaded %d %s nodes", len(rows), label)

    by_triple: dict[tuple[Rel, Label, Label], list[dict[str, Any]]] = {}
    for e in graph.edges:
        by_triple.setdefault((e.rel, e.src_label, e.dst_label), []).append(
            {"src": e.src_key, "dst": e.dst_key, "props": e.props}
        )
    for (rel, src, dst), rows in by_triple.items():
        write_batches(
            driver, _EDGE_QUERY.format(rel=rel, src=src, dst=dst), rows, source=SOURCE
        )
        log.info("loaded %d %s edges (%s -> %s)", len(rows), rel, src, dst)

    skipped = {k: v for k, v in graph.stats.items() if k.startswith(("skipped", "edges_dropped", "in_tactic"))}
    log.info("skipped/dropped: %s", skipped)
