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
