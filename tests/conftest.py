from collections.abc import Iterator

import pytest
from neo4j import Driver, GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from redstring_cti.config import get_settings


@pytest.fixture(scope="session")
def driver() -> Iterator[Driver]:
    s = get_settings()
    drv = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
    try:
        drv.verify_connectivity()
    except ServiceUnavailable:
        drv.close()
        pytest.skip("Neo4j is not running (make up)")
    yield drv
    drv.close()


_TEST_KEY = "coalesce(n.attack_id, n.cwe_id, n.capec_id, n.cve_id) CONTAINS '-TEST-'"


@pytest.fixture
def isolated_test_graph(driver: Driver) -> Iterator[None]:
    """Fixture nodes use '-TEST-' ids and source_version 'test'. Refuse to run if anything
    else carries such an id, and delete only nodes matching both conditions afterwards."""
    with driver.session() as session:
        clash = session.run(
            f"MATCH (n) WHERE {_TEST_KEY} AND n.source_version <> 'test' RETURN count(n) AS c"
        ).single()
        assert clash and clash["c"] == 0, "'-TEST-' ids exist outside source_version 'test'"
        session.run(f"MATCH (n) WHERE {_TEST_KEY} AND n.source_version = 'test' DETACH DELETE n").consume()
    yield
    with driver.session() as session:
        session.run(f"MATCH (n) WHERE {_TEST_KEY} AND n.source_version = 'test' DETACH DELETE n").consume()
