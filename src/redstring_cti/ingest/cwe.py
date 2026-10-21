"""CWE (Common Weakness Enumeration) ingester: weaknesses and their ChildOf hierarchy."""

import logging
import zipfile
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO
from xml.etree import ElementTree as ET

from neo4j import Driver
from pydantic import BaseModel

from redstring_cti.graph.loader import write_edges, write_nodes
from redstring_cti.ingest.common import Edge, Node, clean_text

log = logging.getLogger(__name__)

SOURCE = "cwe"
KEY_PROP = "cwe_id"
SKIP_STATUS = {"Deprecated"}


class CweGraph(BaseModel):
    version: str
    nodes: list[Node]
    edges: list[Edge]
    stats: dict[str, int]


def local(tag: str) -> str:
    return tag.rpartition("}")[2]


def text_of(elem: ET.Element | None) -> str | None:
    return clean_text("".join(elem.itertext())) if elem is not None else None


def child(elem: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in elem if local(c.tag) == name), None)


@contextmanager
def open_xml(path: Path) -> Iterator[IO[bytes]]:
    """Open an XML file, or the first member of a .zip, as a binary stream."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as z, z.open(z.namelist()[0]) as f:
            yield f
    else:
        with path.open("rb") as f:
            yield f


def parse_cwe(path: Path) -> CweGraph:
    stats: Counter[str] = Counter()
    nodes: dict[str, Node] = {}
    parents: dict[tuple[str, str], set[str]] = {}  # (child, parent) -> view ids
    version = "unknown"

    with open_xml(path) as f:
        for event, elem in ET.iterparse(f, events=("start", "end")):
            name = local(elem.tag)
            if event == "start":
                if name == "Weakness_Catalog":
                    version = elem.attrib.get("Version", version)
                continue
            if name != "Weakness":
                continue
            cwe_id = f"CWE-{elem.attrib['ID']}"
            if elem.attrib.get("Status") in SKIP_STATUS:
                stats[f"skipped_{elem.attrib['Status'].lower()}:Weakness"] += 1
            else:
                props = {
                    "name": elem.attrib.get("Name"),
                    "description": text_of(child(elem, "Description")),
                    "abstraction": elem.attrib.get("Abstraction"),
                    "status": elem.attrib.get("Status"),
                }
                nodes[cwe_id] = Node(
                    label="CWE",
                    key_prop=KEY_PROP,
                    key=cwe_id,
                    props={k: v for k, v in props.items() if v is not None},
                )
                related = child(elem, "Related_Weaknesses")
                for rw in related if related is not None else []:
                    if rw.attrib.get("Nature") == "ChildOf":
                        parent = f"CWE-{rw.attrib['CWE_ID']}"
                        parents.setdefault((cwe_id, parent), set()).add(rw.attrib.get("View_ID", ""))
            elem.clear()

    edges: list[Edge] = []
    for (src, dst), views in sorted(parents.items()):
        if dst not in nodes:
            stats["edges_dropped_endpoint_not_kept:CHILD_OF"] += 1
            continue
        edges.append(
            Edge(
                rel="CHILD_OF",
                src_label="CWE",
                src_prop=KEY_PROP,
                src_key=src,
                dst_label="CWE",
                dst_prop=KEY_PROP,
                dst_key=dst,
                props={"views": sorted(v for v in views if v)},
            )
        )
    stats["nodes:CWE"] = len(nodes)
    stats["edges:CHILD_OF"] = len(edges)
    return CweGraph(
        version=version, nodes=list(nodes.values()), edges=edges, stats=dict(sorted(stats.items()))
    )


def load_cwe(driver: Driver, graph: CweGraph) -> None:
    write_nodes(driver, graph.nodes, source=SOURCE, version=graph.version)
    write_edges(driver, graph.edges, source=SOURCE)
    log.info("cwe skipped/dropped: %s", {k: v for k, v in graph.stats.items() if "skipped" in k or "dropped" in k})
