"""Copy one Neo4j database into a fresh, empty one (compact store files), keeping labels, properties, relationships and schema.

Used to build the Space's graph: prune the CVEs the demo does not need in a copy of the full graph, then run this so the
dump is not padded with the space left by deleted records (neo4j-admin copy is Enterprise-only)."""

import argparse
import os
import time

from neo4j import GraphDatabase

from redstring_cti.graph.loader import apply_schema

BATCH = 2000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", default="bolt://localhost:7688")
    ap.add_argument("--target", default="bolt://localhost:7689")
    args = ap.parse_args()
    auth = ("neo4j", os.environ["NEO4J_PASSWORD"])
    src, dst = GraphDatabase.driver(args.source, auth=auth), GraphDatabase.driver(args.target, auth=auth)
    apply_schema(dst)
    started = time.time()

    labels = [r["l"] for r in src.execute_query("CALL db.labels() YIELD label RETURN label AS l").records]
    for label in labels:  # a temporary index makes the relationship pass fast
        dst.execute_query(f"CREATE INDEX copy_{label.lower()} IF NOT EXISTS FOR (n:`{label}`) ON (n._old)")
    dst.execute_query("CALL db.awaitIndexes(300)")

    total = 0
    cursor = 0
    while True:
        rows = src.execute_query(
            "MATCH (n) WITH n, elementId(n) AS eid ORDER BY eid SKIP $skip LIMIT $n RETURN eid, labels(n) AS labels, properties(n) AS props", skip=cursor, n=BATCH).records
        if not rows:
            break
        by_labels: dict[tuple[str, ...], list[dict[str, object]]] = {}
        for r in rows:
            by_labels.setdefault(tuple(sorted(r["labels"])), []).append({"old": r["eid"], "props": r["props"]})
        for lbls, items in by_labels.items():
            label_expr = ":".join(f"`{x}`" for x in lbls)
            dst.execute_query(f"UNWIND $items AS i CREATE (n:{label_expr}) SET n = i.props, n._old = i.old", items=items)
        total += len(rows)
        cursor += BATCH
    print(f"nodes copied: {total} in {time.time() - started:.0f}s")

    rels = 0
    cursor = 0
    while True:
        rows = src.execute_query(
            "MATCH (a)-[r]->(b) WITH a, r, b, elementId(r) AS rid ORDER BY rid SKIP $skip LIMIT $n "
            "RETURN elementId(a) AS a, labels(a) AS al, elementId(b) AS b, labels(b) AS bl, type(r) AS t, properties(r) AS props", skip=cursor, n=BATCH).records
        if not rows:
            break
        groups: dict[tuple[str, str, str], list[dict[str, object]]] = {}
        for r in rows:
            la = next(x for x in r["al"] if x not in ("Searchable", "Reference"))
            lb = next(x for x in r["bl"] if x not in ("Searchable", "Reference"))
            groups.setdefault((la, r["t"], lb), []).append({"a": r["a"], "b": r["b"], "props": r["props"]})
        for (la, t, lb), items in groups.items():
            dst.execute_query(f"UNWIND $items AS i MATCH (a:`{la}` {{_old: i.a}}), (b:`{lb}` {{_old: i.b}}) CREATE (a)-[r:`{t}`]->(b) SET r = i.props", items=items)
        rels += len(rows)
        cursor += BATCH
    print(f"relationships copied: {rels} in {time.time() - started:.0f}s")

    dst.execute_query("MATCH (n) REMOVE n._old")
    for label in labels:
        dst.execute_query(f"DROP INDEX copy_{label.lower()} IF EXISTS")
    dst.execute_query("CALL db.awaitIndexes(600)")
    for name, query in [("nodes", "MATCH (n) RETURN count(n) AS n"), ("edges", "MATCH ()-[r]->() RETURN count(r) AS n")]:
        print(name, "source", src.execute_query(query).records[0]["n"], "target", dst.execute_query(query).records[0]["n"])


if __name__ == "__main__":
    main()
