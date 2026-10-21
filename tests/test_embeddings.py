from pathlib import Path
from typing import Any

import numpy as np
import pytest
from neo4j import Driver

from redstring_cti.graph.embeddings import (
    DIMENSIONS,
    MAX_DESCRIPTION_CHARS,
    build_embeddings,
    embed_query,
    embedding_key,
    embedding_text,
    load_model,
)
from redstring_cti.graph.loader import apply_schema
from redstring_cti.ingest.attack import load_attack, parse_attack

FIXTURES = Path(__file__).parent / "fixtures"


def test_embedding_text_includes_aliases_and_truncates() -> None:
    text = embedding_text("Group", "APT29", "Russian group.", ["APT29", "Cozy Bear", "NOBELIUM"])
    assert text == "Group: APT29 (also known as: Cozy Bear, NOBELIUM). Russian group."
    assert "Cozy Bear" not in embedding_text("Group", "APT29", "d", ["Cozy Bear"], with_aliases=False)
    long = embedding_text("CWE", "X", "a" * 5000)
    assert len(long) == len("CWE: X. ") + MAX_DESCRIPTION_CHARS
    assert embedding_text("Technique", "T", None) == "Technique: T."


def test_embedding_key_tracks_text_and_model() -> None:
    assert embedding_key("a") == embedding_key("a")
    assert embedding_key("a") != embedding_key("b")
    assert embedding_key("a", model="m1") != embedding_key("a", model="m2")


class FakeModel:
    """Deterministic 384-d unit vectors derived from the text (no download needed)."""

    def __init__(self) -> None:
        self.calls = 0

    def encode(self, texts: list[str], **_: Any) -> np.ndarray:
        self.calls += len(texts)
        out = []
        for t in texts:
            rng = np.random.default_rng(abs(hash(t)) % (2**32))
            v = rng.normal(size=DIMENSIONS)
            out.append(v / np.linalg.norm(v))
        return np.array(out, dtype=np.float32)


def test_build_embeddings_is_incremental_and_scoped(driver: Driver, isolated_test_graph: None) -> None:
    apply_schema(driver)
    load_attack(driver, parse_attack(FIXTURES / "attack_mini.json", "test"))
    with driver.session() as session:
        uids = {r["uid"] for r in session.run("MATCH (n {source_version: 'test'}) RETURN n.uid AS uid")}
        real_before = session.run(
            "MATCH (n:Technique {attack_id: 'T1566.001'}) RETURN n.embedding_key AS k"
        ).single()
    model = FakeModel()

    first = build_embeddings(driver, cve_scope="none", model=model, uids=uids)  # type: ignore[arg-type]
    assert first == {"selected": 10, "embedded": 10, "skipped_unchanged": 0}
    again = build_embeddings(driver, cve_scope="none", model=model, uids=uids)  # type: ignore[arg-type]
    assert again == {"selected": 10, "embedded": 0, "skipped_unchanged": 10}
    assert model.calls == 10  # the second run did not call the model

    with driver.session() as session:
        session.run("MATCH (n:Group {attack_id: 'G-TEST-1'}) SET n.description = 'changed'").consume()
    changed = build_embeddings(driver, cve_scope="none", model=model, uids=uids)  # type: ignore[arg-type]
    assert changed["embedded"] == 1

    with driver.session() as session:
        row = session.run(
            "MATCH (n:Group {attack_id: 'G-TEST-1'}) RETURN size(n.embedding) AS d, n.embedding_model AS m"
        ).single()
        assert row and row["d"] == DIMENSIONS and row["m"] == "BAAI/bge-small-en-v1.5"
        stored = session.run(
            "MATCH (n:Group {attack_id: 'G-TEST-1'}) RETURN n.embedding AS v"
        ).single()
        assert stored
        hits = session.run(  # querying with a node's own stored vector must return that node first
            "CALL db.index.vector.queryNodes('ref_vec', 3, $v) YIELD node, score "
            "RETURN node.uid AS uid, score",
            v=stored["v"],
        ).data()
        assert hits[0]["uid"] == "Group:G-TEST-1" and hits[0]["score"] > 0.999
        real_after = session.run(
            "MATCH (n:Technique {attack_id: 'T1566.001'}) RETURN n.embedding_key AS k"
        ).single()
    assert real_before == real_after  # real nodes untouched


@pytest.fixture(scope="module")
def real_model() -> Any:
    return load_model()


# (index, query, uid prefixes that count as a hit | None, description substring that counts | None).
# A bare name like "Cozy Bear" is deliberately absent: vectors match meaning, not names, so name and
# alias lookup is the full-text index's job (test_fulltext_resolves_aliases).
SEMANTIC_CASES: list[tuple[str, str, list[str] | None, str | None]] = [
    ("ref_vec", "NOBELIUM Russian espionage group", ["Group:G0016"], None),
    ("ref_vec", "how do attackers abuse scheduled tasks for persistence", ["Technique:T1053"], None),
    ("ref_vec", "SQL injection through unsanitized input", ["CWE:CWE-89", "CAPEC:CAPEC-66"], None),
    ("ref_vec", "sending emails with malicious attachments", ["Technique:T1566"], None),
    ("ref_vec", "ransomware encrypting files", ["Technique:T1486"], None),
    ("cve_vec", "Windows MSHTML platform spoofing vulnerability", None, "MSHTML"),
]


@pytest.mark.parametrize(("index", "query", "prefixes", "needle"), SEMANTIC_CASES)
def test_semantic_search_finds_expected_node(
    driver: Driver, real_model: Any, index: str, query: str, prefixes: list[str] | None, needle: str | None
) -> None:
    with driver.session() as session:
        n = session.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g.embedding IS NOT NULL AS ok").single()
        if not n or not n["ok"]:
            pytest.skip("embeddings not built (make embed)")
        rows = session.run(
            "CALL db.index.vector.queryNodes($index, 5, $v) YIELD node "
            "RETURN node.uid AS uid, node.description AS description",
            index=index,
            v=embed_query(real_model, query),
        ).data()
    if prefixes:
        assert any(r["uid"].startswith(p) for r in rows for p in prefixes), f"{query!r} -> {[r['uid'] for r in rows]}"
    if needle:
        assert any(needle in (r["description"] or "") for r in rows), f"{query!r} -> {[r['uid'] for r in rows]}"


def test_fulltext_resolves_aliases(driver: Driver) -> None:
    with driver.session() as session:
        rows = session.run(
            "CALL db.index.fulltext.queryNodes('text_search', $q) YIELD node, score "
            "RETURN node.uid AS uid LIMIT 3",
            q='"Cozy Bear"',
        )
        top = [r["uid"] for r in rows]
    if not top:
        pytest.skip("graph not loaded (make load)")
    assert "Group:G0016" in top, top
