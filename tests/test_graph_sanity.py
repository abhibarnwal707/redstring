import pytest
from neo4j import Driver

from redstring_cti.config import ATTACK_VERSION
from redstring_cti.graph.queries import SANITY_QUERIES


@pytest.fixture(scope="module")
def graph_loaded(driver: Driver) -> None:
    with driver.session() as session:
        n = session.run(
            "MATCH (g:Group {source_version: $v}) RETURN count(g) AS n", v=ATTACK_VERSION
        ).single()
    if not n or n["n"] == 0:
        pytest.skip("ATT&CK is not loaded (make load)")


@pytest.mark.parametrize("name", sorted(SANITY_QUERIES))
def test_sanity_query_returns_rows(driver: Driver, graph_loaded: None, name: str) -> None:
    cypher, params, minimum = SANITY_QUERIES[name]
    with driver.session() as session:
        rows = list(session.run(cypher, **params))
    assert len(rows) >= minimum, f"{name}: got {len(rows)} rows, expected >= {minimum}"
