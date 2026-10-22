"""Baseline 1b: vector search plus ONE hop of graph expansion (the strongest non-agent retrieval we compare against).

Plain vector RAG sees node text only, so relationship questions are impossible for it by construction. This variant gives it
the same nearest nodes AND their direct neighbours with the relationship, which is what a careful RAG engineer would try
before building an agent. It still cannot filter, count, rank, intersect or follow more than one hop."""

import time
from dataclasses import dataclass

from neo4j import Driver
from sentence_transformers import SentenceTransformer

from redstring_cti.graph.ids import key_expr
from redstring_cti.llm import GroqLLM
from redstring_cti.retrieval import vector_rag
from redstring_cti.retrieval.common import SystemAnswer, ids_in

EXPAND_TOP = 4  # expand the best few concept hits (the rest stay as plain records)
NEIGHBORS_PER_NODE = 12
MAX_TOKENS = 450

SYSTEM = (
    "You answer cyber-threat-intelligence questions using ONLY the context provided. The context has two parts: records "
    "(each starting with its ID) and links, written 'A -RELATION-> B', which are relationships in the knowledge graph. "
    "Do not use outside knowledge. If the context does not contain the answer, say it is not found in the knowledge graph.\n"
    + vector_rag.FINAL_RULES
)

_NEIGHBORS = (
    "MATCH (n:Searchable {uid: $uid})-[r]-(m) "
    "RETURN " + key_expr("n") + " AS a, type(r) AS rel, startNode(r) = n AS outgoing, " + key_expr("m") + " AS b, m.name AS name "
    "LIMIT $limit"
)


@dataclass
class Link:
    a: str
    rel: str
    b: str
    b_name: str

    def line(self) -> str:
        return f"{self.a} -{self.rel}-> {self.b} ({self.b_name})"


def expand(driver: Driver, hits: list[vector_rag.Hit]) -> list[Link]:
    links: list[Link] = []
    for hit in [h for h in hits if h.label != "CVE"][:EXPAND_TOP]:
        rows, _, _ = driver.execute_query(_NEIGHBORS, uid=f"{hit.label}:{hit.id}", limit=NEIGHBORS_PER_NODE)
        for r in rows:
            a, b = (r["a"], r["b"]) if r["outgoing"] else (r["b"], r["a"])
            links.append(Link(a, r["rel"], b, r["name"] or ""))
    unique: dict[str, Link] = {}
    for link in links:
        unique.setdefault(link.line(), link)
    return list(unique.values())


def answer(llm: GroqLLM, driver: Driver, model: SentenceTransformer, question: str) -> SystemAnswer:
    started = time.perf_counter()
    hits = vector_rag.retrieve(driver, model, question)
    links = expand(driver, hits)
    context = "Records:\n" + vector_rag.format_context(hits) + "\n\nLinks:\n" + "\n".join(link.line() for link in links)
    result = llm.complete([{"role": "system", "content": SYSTEM}, {"role": "user", "content": f"Context:\n{context}\n\nQuestion: {question}"}], max_tokens=MAX_TOKENS)
    return SystemAnswer(text=result.text, evidence_ids=ids_in(context), calls=[result], wall_s=time.perf_counter() - started,
                        extra={"retrieved": [h.id for h in hits], "links": len(links)})
