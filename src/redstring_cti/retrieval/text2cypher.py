"""Baseline 2: graph-only Text2Cypher. The LLM writes Cypher from the schema plus a few worked examples,
the query runs through the read-only guardrails, and the LLM turns the rows into a cited answer.

It is strong when the question maps cleanly to a graph pattern and weak on fuzzy questions and on
aggregations it has not seen. A failed query is retried once with the error message.
"""

import json
import re
import time

from neo4j import Driver

from redstring_cti.gold.models import GoldQuestion
from redstring_cti.llm import GroqLLM
from redstring_cti.mcp_server.guardrails import (
    CypherExecutionError,
    GuardrailError,
    run_read,
)
from redstring_cti.retrieval.common import FINAL_RULES, SystemAnswer, ids_in

# Worked examples come from DEV questions only (never the held-out test set) and are excluded from
# the evaluation, so a system is never scored on its own prompt. They cover each query pattern once.
FEWSHOT_IDS = ("q001", "q017", "q024", "q030", "q033", "q041", "q049", "q059", "q087", "q101", "q115")

GEN_MAX_TOKENS = 450
VERBALISE_MAX_TOKENS = 350
MAX_ROWS_IN_PROMPT = 60
MAX_CELL_CHARS = 160

SCHEMA = """\
Neo4j graph schema. Every node has the property named below as its key.
Nodes:
  (:Group {attack_id e.g. G0016, name, aliases[], description})
  (:Technique {attack_id e.g. T1566 or T1566.001, name, description, is_subtechnique, platforms[]})
  (:Tactic {attack_id e.g. TA0001, name, shortname e.g. 'initial-access','execution','impact','stealth'})
  (:Software {attack_id e.g. S0154, name, type 'malware'|'tool', aliases[]})
  (:Mitigation {attack_id e.g. M1017, name, description})
  (:Campaign {attack_id e.g. C0024, name, first_seen, last_seen})
  (:CAPEC {capec_id e.g. CAPEC-66, name, description, likelihood, severity})
  (:CWE {cwe_id e.g. CWE-89, name, description, abstraction})
  (:CVE {cve_id, description, cvss_score, cvss_severity, cvss_version, published, kev (boolean),
         kev_date_added ('YYYY-MM-DD' string), known_ransomware_use (boolean)})
Relationships:
  (Group|Software|Campaign)-[:USES]->(Technique)    (Group|Campaign)-[:USES]->(Software)
  (Campaign)-[:ATTRIBUTED_TO]->(Group)              (Mitigation)-[:MITIGATES]->(Technique)
  (Technique)-[:SUBTECHNIQUE_OF]->(Technique)       (Technique)-[:IN_TACTIC]->(Tactic)
  (CAPEC)-[:MAPS_TO]->(Technique)                   (CAPEC)-[:EXPLOITS]->(CWE)
  (CWE)-[:CHILD_OF]->(CWE)                          (CAPEC)-[:CHILD_OF]->(CAPEC)
  (CVE)-[:HAS_WEAKNESS]->(CWE)
Rules: read-only Cypher. Match entities by their key property, or by name / aliases when only a name is
given. Return DISTINCT ids in a column named `id` (the key property). For counts return one column
`value`; for rankings return `id` and `value` ordered by value DESC and use LIMIT. Always add ORDER BY.
Output only the Cypher query inside a ```cypher block."""

_FENCE = re.compile(r"```(?:cypher)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)

VERBALISE_SYSTEM = (
    "You answer a cyber-threat-intelligence question from the rows a database query returned. The query was "
    "written to answer this question, so non-empty rows ARE the answer: report them, do not second-guess the "
    "query. Use ONLY those rows. If there are no rows, the answer is not found in the knowledge graph.\n" + FINAL_RULES
)


def build_fewshot(gold: list[GoldQuestion]) -> str:
    by_id = {q.id: q for q in gold}
    parts = []
    for qid in FEWSHOT_IDS:
        q = by_id[qid]
        if q.split != "dev":
            raise ValueError(f"few-shot example {qid} is not a dev question")
        parts.append(f"Question: {q.question}\n```cypher\n{q.gold_cypher}\n```")
    return "\n\n".join(parts)


def extract_cypher(text: str) -> str:
    m = _FENCE.search(text)
    return (m.group(1) if m else text).strip()


def rows_for_prompt(rows: list[dict[str, object]]) -> str:
    shown = [{k: (str(v)[:MAX_CELL_CHARS]) for k, v in r.items()} for r in rows[:MAX_ROWS_IN_PROMPT]]
    suffix = f"\n... {len(rows) - MAX_ROWS_IN_PROMPT} more rows not shown" if len(rows) > MAX_ROWS_IN_PROMPT else ""
    return "\n".join(json.dumps(r) for r in shown) + suffix


def answer(llm: GroqLLM, driver: Driver, fewshot: str, question: str) -> SystemAnswer:
    started = time.perf_counter()
    system = f"{SCHEMA}\n\nExamples:\n\n{fewshot}"
    messages = [{"role": "system", "content": system}, {"role": "user", "content": f"Question: {question}"}]
    calls = []
    cypher = executed = None
    rows: list[dict[str, object]] | None = None
    error: str | None = None

    for attempt in range(2):  # one retry, passing the error back to the model
        gen = llm.complete(messages, max_tokens=GEN_MAX_TOKENS)
        calls.append(gen)
        cypher = extract_cypher(gen.text)
        try:
            rows, executed = run_read(driver, cypher)
            error = None
            break
        except (GuardrailError, CypherExecutionError) as exc:
            error = str(exc)
            messages = [
                *messages,
                {"role": "assistant", "content": gen.text},
                {"role": "user", "content": f"That query failed: {error}\nReturn a corrected query in a ```cypher block."},
            ]

    if rows is None:
        return SystemAnswer(
            text=f"ERROR: could not run a valid query ({error})",
            calls=calls, wall_s=time.perf_counter() - started, cypher=cypher, error=error,
        )

    body = rows_for_prompt(rows) if rows else "(no rows returned)"
    verbal = llm.complete(
        [
            {"role": "system", "content": VERBALISE_SYSTEM},
            {"role": "user", "content": f"Question: {question}\n\nQuery result rows ({len(rows)}):\n{body}"},
        ],
        max_tokens=VERBALISE_MAX_TOKENS,
    )
    calls.append(verbal)
    return SystemAnswer(
        text=verbal.text,
        evidence_ids=ids_in(json.dumps(rows, default=str)),
        calls=calls,
        wall_s=time.perf_counter() - started,
        cypher=executed,
        rows=len(rows),
        error=None,
    )
