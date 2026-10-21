"""Baseline 1: vector-only RAG. Embed the question, fetch the nearest nodes, let the LLM answer.

This is the system the agent must beat on multi-hop questions: it can find text that sounds similar
but cannot join facts across documents.
"""

import time
from dataclasses import dataclass

from neo4j import Driver
from sentence_transformers import SentenceTransformer

from redstring_cti.graph.embeddings import embed_query
from redstring_cti.llm import GroqLLM
from redstring_cti.retrieval.common import FINAL_RULES, SystemAnswer, ids_in

K_REF = 10  # concept nodes (techniques, groups, CWEs, ...)
K_CVE = 5  # CVEs, searched in their own index so they cannot crowd out concepts
DESCRIPTION_CHARS = 240
MAX_TOKENS = 450  # Groq reserves the full completion budget against the per-minute quota

SYSTEM = (
    "You answer cyber-threat-intelligence questions using ONLY the context records provided. "
    "Each record starts with its ID. Do not use outside knowledge. If the records do not contain the "
    "answer, say it is not found in the knowledge graph.\n" + FINAL_RULES
)

_SEARCH = """
CALL db.index.vector.queryNodes($index, $k, $vec) YIELD node, score
RETURN node.uid AS uid, [l IN labels(node) WHERE NOT l IN ['Searchable', 'Reference']][0] AS label,
       node.name AS name, node.description AS description, score
"""


@dataclass
class Hit:
    id: str
    label: str
    name: str
    description: str
    score: float


def retrieve(driver: Driver, model: SentenceTransformer, question: str) -> list[Hit]:
    vec = embed_query(model, question)
    hits: list[Hit] = []
    with driver.session() as session:
        for index, k in (("ref_vec", K_REF), ("cve_vec", K_CVE)):
            for r in session.run(_SEARCH, index=index, k=k, vec=vec):
                hits.append(
                    Hit(
                        id=str(r["uid"]).split(":", 1)[1],
                        label=r["label"] or "",
                        name=r["name"] or "",
                        description=(r["description"] or "")[:DESCRIPTION_CHARS],
                        score=float(r["score"]),
                    )
                )
    return hits


def format_context(hits: list[Hit]) -> str:
    return "\n".join(f"{h.id} | {h.label} | {h.name} | {h.description}" for h in hits)


def answer(llm: GroqLLM, driver: Driver, model: SentenceTransformer, question: str) -> SystemAnswer:
    started = time.perf_counter()
    hits = retrieve(driver, model, question)
    context = format_context(hits)
    result = llm.complete(
        [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Context records:\n{context}\n\nQuestion: {question}"},
        ],
        max_tokens=MAX_TOKENS,
    )
    return SystemAnswer(
        text=result.text,
        evidence_ids=ids_in(context),
        calls=[result],
        wall_s=time.perf_counter() - started,
        extra={"retrieved": [h.id for h in hits]},
    )
