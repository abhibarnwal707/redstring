import pytest
from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

from redstring_cti.config import get_settings


def test_neo4j_connects() -> None:
    s = get_settings()
    driver = GraphDatabase.driver(s.neo4j_uri, auth=(s.neo4j_user, s.neo4j_password))
    try:
        driver.verify_connectivity()
    except ServiceUnavailable:
        pytest.skip("Neo4j is not running (docker compose up -d)")
    finally:
        driver.close()
