from typing import Any

from neo4j import Driver

from redstring_cti.retrieval import vector_expand, vector_rag
from redstring_cti.retrieval.vector_rag import Hit


class FakeDriver:
    def __init__(self, rows: list[dict[str, Any]]) -> None:
        self.rows, self.calls = rows, []  # type: ignore[var-annotated]

    def execute_query(self, query: str, **params: Any) -> tuple[list[dict[str, Any]], Any, Any]:
        self.calls.append(params)
        return self.rows, None, None


def hit(label: str, id_: str) -> Hit:
    return Hit(id=id_, label=label, name=id_, description="", score=0.9)


def test_expand_orients_edges_dedupes_and_skips_cves() -> None:
    rows = [{"a": "G1", "rel": "USES", "outgoing": True, "b": "T1", "name": "Tech"},
            {"a": "G1", "rel": "USES", "outgoing": False, "b": "S1", "name": "Soft"}]  # S1 -USES-> G1 (incoming edge)
    driver = FakeDriver(rows)
    links = vector_expand.expand(driver, [hit("Group", "G1"), hit("CVE", "CVE-2024-1"), hit("Group", "G1")])  # type: ignore[arg-type]
    assert [link.line() for link in links] == ["G1 -USES-> T1 (Tech)", "S1 -USES-> G1 (Soft)"]  # the duplicate G1 expansion collapses
    assert all(call["uid"] == "Group:G1" for call in driver.calls) and len(driver.calls) == 2  # the CVE hit was not expanded


def test_only_the_best_few_hits_are_expanded() -> None:
    driver = FakeDriver([])
    vector_expand.expand(driver, [hit("Technique", f"T{i}") for i in range(10)])  # type: ignore[arg-type]
    assert len(driver.calls) == vector_expand.EXPAND_TOP


def test_neighbour_query_returns_real_links(driver: Driver) -> None:
    links = vector_expand.expand(driver, [vector_rag.Hit(id="G0016", label="Group", name="APT29", description="", score=1.0)])
    assert links and all(link.a and link.rel and link.b for link in links)
    assert any(link.a == "G0016" and link.rel == "USES" and link.b.startswith("T") for link in links)
