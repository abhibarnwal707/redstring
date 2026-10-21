"""Neo4j connection, schema application and the top-level `make load` entry point."""

import logging
import re
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from neo4j import Driver, GraphDatabase, ManagedTransaction

from redstring_cti.config import ATTACK_VERSION, RAW_DIR, get_settings
from redstring_cti.ingest.common import Edge, Node, batched

log = logging.getLogger(__name__)

SCHEMA_PATH = Path(__file__).with_name("schema.cypher")
BATCH_SIZE = 1000


def get_driver() -> Driver:
    s = get_settings()
    return GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))


def apply_schema(driver: Driver) -> None:
    statements = [s.strip() for s in SCHEMA_PATH.read_text().split(";") if s.strip()]
    with driver.session() as session:
        for stmt in statements:
            session.run(stmt).consume()


def write_batches(
    driver: Driver,
    query: str,
    rows: Iterable[dict[str, Any]],
    *,
    size: int = BATCH_SIZE,
    **params: Any,
) -> int:
    """Run `query` once per batch with $rows bound; returns the number of rows sent."""
    sent = 0

    def run(tx: ManagedTransaction, batch: list[dict[str, Any]]) -> None:
        tx.run(query, rows=batch, **params).consume()

    with driver.session() as session:
        for batch in batched(rows, size):
            session.execute_write(run, batch)
            sent += len(batch)
    return sent


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# Labels, relationship types and key properties are interpolated into Cypher, so they must
# be plain identifiers. They always come from constants in the ingesters, never from data.
_NODE_QUERY = """
UNWIND $rows AS row
MERGE (n:{label} {{{key_prop}: row.key}})
SET n += row.props, n:Searchable, n.uid = row.uid,
    n.source = $source, n.source_version = $version, n.ingested_at = $ingested_at
"""
_EDGE_QUERY = """
UNWIND $rows AS row
MATCH (a:{src} {{{src_prop}: row.src}})
MATCH (b:{dst} {{{dst_prop}: row.dst}})
MERGE (a)-[r:{rel}]->(b)
SET r += row.props, r.source = $source
"""


def _ident(*names: str) -> None:
    for name in names:
        if not _IDENT.fullmatch(name):
            raise ValueError(f"unsafe identifier: {name!r}")


def write_nodes(driver: Driver, nodes: Iterable[Node], *, source: str, version: str) -> dict[str, int]:
    """MERGE nodes grouped by (label, key property). Returns rows written per label."""
    ingested_at = datetime.now(UTC).isoformat(timespec="seconds")
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for n in nodes:
        groups.setdefault((n.label, n.key_prop), []).append(
            {"key": n.key, "uid": n.uid, "props": n.props}
        )
    written: dict[str, int] = {}
    for (label, key_prop), rows in groups.items():
        _ident(label, key_prop)
        query = _NODE_QUERY.format(label=label, key_prop=key_prop)
        written[label] = write_batches(
            driver, query, rows, source=source, version=version, ingested_at=ingested_at
        )
        log.info("loaded %d %s nodes", written[label], label)
    return written


def write_edges(driver: Driver, edges: Iterable[Edge], *, source: str) -> dict[str, int]:
    """MERGE edges grouped by (rel, endpoint labels). Returns rows written per relationship type."""
    groups: dict[tuple[str, str, str, str, str], list[dict[str, Any]]] = {}
    for e in edges:
        groups.setdefault((e.rel, e.src_label, e.src_prop, e.dst_label, e.dst_prop), []).append(
            {"src": e.src_key, "dst": e.dst_key, "props": e.props}
        )
    written: dict[str, int] = {}
    for (rel, src, src_prop, dst, dst_prop), rows in groups.items():
        _ident(rel, src, src_prop, dst, dst_prop)
        query = _EDGE_QUERY.format(
            rel=rel, src=src, src_prop=src_prop, dst=dst, dst_prop=dst_prop
        )
        n = write_batches(driver, query, rows, source=source)
        written[rel] = written.get(rel, 0) + n
        log.info("loaded %d %s edges (%s -> %s)", n, rel, src, dst)
    return written


def existing_keys(driver: Driver, label: str, key_prop: str) -> set[str]:
    _ident(label, key_prop)
    with driver.session() as session:
        result = session.run(f"MATCH (n:{label}) RETURN n.{key_prop} AS k")
        return {r["k"] for r in result}


def graph_counts(driver: Driver) -> dict[str, dict[str, int]]:
    with driver.session() as session:
        nodes = session.run(
            "MATCH (n) UNWIND labels(n) AS l WITH l, count(*) AS c WHERE l <> 'Searchable' RETURN l, c"
        )
        rels = session.run("MATCH ()-[r]->() RETURN type(r) AS t, count(*) AS c")
        return {
            "nodes": {r["l"]: r["c"] for r in nodes},
            "edges": {r["t"]: r["c"] for r in rels},
        }


def main() -> None:
    from redstring_cti.ingest.attack import load_attack, parse_attack
    from redstring_cti.ingest.capec import load_capec, parse_capec
    from redstring_cti.ingest.cwe import load_cwe, parse_cwe

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.WARNING)  # drop "index already exists" notices
    driver = get_driver()
    try:
        apply_schema(driver)
        graph = parse_attack(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json", ATTACK_VERSION)
        load_attack(driver, graph)
        load_cwe(driver, parse_cwe(RAW_DIR / "cwec_latest.xml.zip"))
        load_capec(driver, parse_capec(RAW_DIR / "capec_latest.xml"))
        counts = graph_counts(driver)
        log.info("nodes: %s", counts["nodes"])
        log.info("edges: %s", counts["edges"])
    finally:
        driver.close()


if __name__ == "__main__":
    main()
