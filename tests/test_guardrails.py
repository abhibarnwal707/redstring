import pytest
from neo4j import Driver

from redstring_cti.mcp_server.guardrails import (
    MAX_ROWS,
    CypherExecutionError,
    GuardrailError,
    run_read,
    validate,
)

OK = [
    "MATCH (g:Group {attack_id: 'G0016'})-[:USES]->(t:Technique) RETURN t.attack_id AS id",
    "MATCH (a)-[:USES*1..3]->(b) RETURN b.attack_id AS id",
    "MATCH (a)-[:USES*2]->(b) RETURN b.attack_id AS id LIMIT 10",
    "MATCH (t:Technique) WHERE t.name = 'Create Account' RETURN t.attack_id AS id",  # keyword inside a string
    "MATCH (n) WHERE n.description CONTAINS 'SET the value' RETURN n.name",
    "CALL db.index.fulltext.queryNodes('text_search', 'Cozy Bear') YIELD node RETURN node.attack_id AS id",
    "MATCH (t:Technique) RETURN t.attack_id AS id // DELETE everything",  # keyword inside a comment
]


@pytest.mark.parametrize("q", OK)
def test_safe_queries_pass(q: str) -> None:
    assert validate(q).startswith(q.split(" //")[0].rstrip(";").split(" LIMIT")[0][:20])


@pytest.mark.parametrize(
    "q",
    [
        "MATCH (n) DETACH DELETE n",
        "MATCH (n) SET n.name = 'x' RETURN n",
        "CREATE (:Group {attack_id: 'X'})",
        "MERGE (n:Group {attack_id: 'X'}) RETURN n",
        "MATCH (n) REMOVE n.name",
        "DROP INDEX ref_vec",
        "LOAD CSV FROM 'http://x' AS row RETURN row",
        "CALL dbms.listConfig()",
        "CALL apoc.cypher.run('MATCH (n) DELETE n', {})",
        "MATCH (n) RETURN apoc.text.join([], ',')",
        "CALL { MATCH (n) RETURN n } RETURN n",
        "MATCH (n) FOREACH (x IN [1] | SET n.a = x)",
        "MATCH (n) RETURN n; MATCH (m) RETURN m",
        "MATCH (a)-[:USES*]->(b) RETURN b",
        "MATCH (a)-[:USES*1..]->(b) RETURN b",
        "MATCH (a)-[:USES*..]->(b) RETURN b",
        "MATCH (a)-[:USES*1..9]->(b) RETURN b",
        "MATCH (a)-[:USES*7]->(b) RETURN b",
        "CALL db.labels()",
        "",
    ],
)
def test_dangerous_queries_are_rejected(q: str) -> None:
    with pytest.raises(GuardrailError):
        validate(q)


def test_row_cap_is_added_or_clamped() -> None:
    assert validate("MATCH (n) RETURN n.name;") == f"MATCH (n) RETURN n.name LIMIT {MAX_ROWS}"
    assert validate("MATCH (n) RETURN n.name LIMIT 5") == "MATCH (n) RETURN n.name LIMIT 5"
    assert validate("MATCH (n) RETURN n.name LIMIT 99999").endswith(f"LIMIT {MAX_ROWS}")


def test_strings_are_preserved_when_capping() -> None:
    assert "'LIMIT 5; drop'" in validate("MATCH (n {name: 'LIMIT 5; drop'}) RETURN n.name")


# ------------------------------------------------------------------ against the live database
def test_read_query_runs(driver: Driver) -> None:
    rows, executed = run_read(driver, "MATCH (g:Group) RETURN g.attack_id AS id ORDER BY id")
    assert rows and executed.endswith(f"LIMIT {MAX_ROWS}")
    assert len(rows) <= MAX_ROWS


def test_runaway_query_times_out(driver: Driver) -> None:
    with pytest.raises(CypherExecutionError):
        run_read(driver, "UNWIND range(1, 1000000000) AS x RETURN sum(x) AS s", timeout_s=1.0)


def test_syntax_error_is_reported_for_retry(driver: Driver) -> None:
    with pytest.raises(CypherExecutionError, match="(?i)invalid|syntax|unexpected|expected"):
        run_read(driver, "MATCH (n RETURN n")


def test_write_cannot_slip_through_a_read_transaction(driver: Driver) -> None:
    """Layer 1 on its own: even if the deny-list were bypassed, the server refuses writes in a read tx."""
    from neo4j import unit_of_work

    @unit_of_work(timeout=5)
    def write(tx):  # type: ignore[no-untyped-def]
        return list(tx.run("CREATE (:GuardrailProbe {x: 1}) RETURN 1"))

    with driver.session() as session, pytest.raises(Exception, match="(?i)read|write|not allowed"):
        session.execute_read(write)
    with driver.session() as session:
        assert session.run("MATCH (n:GuardrailProbe) RETURN count(n) AS c").single()["c"] == 0  # type: ignore[index]
