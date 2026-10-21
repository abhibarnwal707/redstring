"""Neo4j connection, schema application and the top-level `make load` entry point."""

import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from neo4j import Driver, GraphDatabase, ManagedTransaction

from redstring_cti.config import ATTACK_VERSION, RAW_DIR, get_settings
from redstring_cti.ingest.common import batched

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

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.WARNING)  # drop "index already exists" notices
    driver = get_driver()
    try:
        apply_schema(driver)
        graph = parse_attack(RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json", ATTACK_VERSION)
        load_attack(driver, graph)
        counts = graph_counts(driver)
        log.info("nodes: %s", counts["nodes"])
        log.info("edges: %s", counts["edges"])
    finally:
        driver.close()


if __name__ == "__main__":
    main()
