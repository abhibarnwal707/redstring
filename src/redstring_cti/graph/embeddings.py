"""Node embeddings: text construction and the build step that stores vectors in Neo4j.

The vectors feed the `searchable_vec` index (384-d, cosine). Model choice is documented in
evals/results/embedding_model_choice.md.
"""

import argparse
import hashlib
import logging
import time
from collections.abc import Sequence
from typing import Any, Literal

from neo4j import Driver
from sentence_transformers import SentenceTransformer

from redstring_cti.graph.loader import get_driver, write_batches

log = logging.getLogger(__name__)

MAX_DESCRIPTION_CHARS = 1000


def embedding_text(
    label: str,
    name: str | None,
    description: str | None,
    aliases: Sequence[str] = (),
    *,
    with_aliases: bool = True,
) -> str:
    """'{label}: {name} (also known as: ...). {description[:1000]}'.

    Aliases matter for Groups and Software ('Cozy Bear' -> APT29): a vector search can then
    match them, instead of relying on the full-text index alone.
    """
    head = f"{label}: {name or ''}"
    others = [a for a in aliases if a and a != name]
    if with_aliases and others:
        head += f" (also known as: {', '.join(others[:12])})"
    return f"{head}. {(description or '')[:MAX_DESCRIPTION_CHARS]}".strip()



MODEL_NAME = "BAAI/bge-small-en-v1.5"
DIMENSIONS = 384
MAX_SEQ_LENGTH = 256
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "  # queries only, never documents
CveScope = Literal["none", "kev", "chain", "all"]
WRITE_BATCH = 2000

_CHAIN = "EXISTS { (n)-[:HAS_WEAKNESS]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:MAPS_TO]->(:Technique) }"
_SELECT = {
    "none": "NOT n:CVE",
    "kev": "NOT n:CVE OR n.kev = true",
    "chain": f"NOT n:CVE OR n.kev = true OR {_CHAIN}",
    "all": "true",
}
_FETCH = """
MATCH (n:Searchable) WHERE {cond}
RETURN n.uid AS uid, [l IN labels(n) WHERE l <> 'Searchable'][0] AS label, n.name AS name,
       n.description AS description, coalesce(n.aliases, []) AS aliases, n.embedding_key AS key
"""
_STORE = """
UNWIND $rows AS row
MATCH (n:Searchable {uid: row.uid})
SET n.embedding = row.vec, n.embedding_key = row.key, n.embedding_model = $model
"""


def embedding_key(text: str, model: str = MODEL_NAME) -> str:
    """Changes whenever the text or the model changes, so unchanged nodes are skipped on rerun."""
    return hashlib.sha1(f"{model}\n{text}".encode()).hexdigest()[:16]


def load_model(device: str | None = None) -> SentenceTransformer:
    import torch  # deferred: only needed when we actually embed

    device = device or ("mps" if torch.backends.mps.is_available() else "cpu")
    model = SentenceTransformer(MODEL_NAME, device=device)
    model.max_seq_length = MAX_SEQ_LENGTH
    return model


def embed_query(model: SentenceTransformer, text: str) -> list[float]:
    vec = model.encode([QUERY_PREFIX + text], normalize_embeddings=True, convert_to_numpy=True)[0]
    return [float(x) for x in vec]


def build_embeddings(
    driver: Driver,
    *,
    cve_scope: CveScope = "chain",
    model: SentenceTransformer | None = None,
    chunk: int = 4096,
    force: bool = False,
    uids: set[str] | None = None,
) -> dict[str, int]:
    """Embed selected nodes that are missing a vector or whose text changed. Returns counts.

    `uids` restricts the run to specific nodes (tests use it so they can never touch real vectors).
    """
    with driver.session() as session:
        rows = [dict(r) for r in session.run(_FETCH.format(cond=_SELECT[cve_scope]))]
    if uids is not None:
        rows = [r for r in rows if r["uid"] in uids]
    todo: list[dict[str, Any]] = []
    for r in rows:
        r["text"] = embedding_text(r["label"], r["name"], r["description"], r["aliases"])
        r["new_key"] = embedding_key(r["text"])
        if force or r["key"] != r["new_key"]:
            todo.append(r)
    stats = {"selected": len(rows), "embedded": len(todo), "skipped_unchanged": len(rows) - len(todo)}
    if not todo:
        return stats

    model = model or load_model()
    todo.sort(key=lambda r: len(r["text"]))  # similar lengths per batch -> little padding
    t0 = time.perf_counter()
    for start in range(0, len(todo), chunk):
        part = todo[start : start + chunk]
        vecs = model.encode(
            [r["text"] for r in part],
            batch_size=64,
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        payload = [
            {"uid": r["uid"], "key": r["new_key"], "vec": [float(x) for x in v]}
            for r, v in zip(part, vecs, strict=True)
        ]
        write_batches(driver, _STORE, payload, size=WRITE_BATCH, model=MODEL_NAME)
        done = start + len(part)
        rate = done / (time.perf_counter() - t0)
        log.info("embedded %d/%d (%.0f docs/s, eta %.0fs)", done, len(todo), rate, (len(todo) - done) / rate)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute node embeddings and store them in Neo4j.")
    parser.add_argument("--cve-scope", choices=["none", "kev", "chain", "all"], default="chain")
    parser.add_argument("--force", action="store_true", help="re-embed even if unchanged")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    driver = get_driver()
    try:
        log.info("embedding stats: %s", build_embeddings(driver, cve_scope=args.cve_scope, force=args.force))
    finally:
        driver.close()


if __name__ == "__main__":
    main()
