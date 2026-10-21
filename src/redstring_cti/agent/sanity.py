"""Phase 6 acceptance: the playbook's 10 sanity questions, asked in natural language of the live agent.

Expected answers are computed from the graph by Cypher, so they stay right if the graph changes.
Run: `uv run python -m redstring_cti.agent.sanity [--llm-chain openai/gpt-oss-20b] [--toolbox mcp|direct]`
Costs about 3,000 model tokens per question on the free tier."""

import argparse
import logging
from dataclasses import dataclass
from typing import Any

from redstring_cti.agent.graph import Agent
from redstring_cti.agent.state import AgentConfig
from redstring_cti.agent.toolbox import DirectToolbox, McpToolbox, Toolbox
from redstring_cti.config import get_settings
from redstring_cti.evaluation import resolve_chain
from redstring_cti.gold.models import GoldQuestion, load_gold
from redstring_cti.graph.embeddings import embed_query, load_model
from redstring_cti.graph.loader import get_driver
from redstring_cti.llm import LLMClient
from redstring_cti.mcp_server import tools
from redstring_cti.retrieval import text2cypher
from redstring_cti.scoring import score_question

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Case:
    key: str  # which playbook sanity query this corresponds to
    question: str
    cypher: str
    style: str = "list"


CASES = [
    Case("apt29_techniques", "Which techniques does APT29 use?",
         "MATCH (:Group {attack_id: 'G0016'})-[:USES]->(t:Technique) RETURN DISTINCT t.attack_id AS id ORDER BY id"),
    Case("subtechniques_of_t1059", "What are the sub-techniques of T1059?",
         "MATCH (s:Technique)-[:SUBTECHNIQUE_OF]->(:Technique {attack_id: 'T1059'}) RETURN DISTINCT s.attack_id AS id ORDER BY id"),
    Case("mitigations_for_phishing", "Which mitigations apply to Phishing (T1566)?",
         "MATCH (m:Mitigation)-[:MITIGATES]->(:Technique {attack_id: 'T1566'}) RETURN DISTINCT m.attack_id AS id ORDER BY id"),
    Case("software_used_by_group", "What software does Transparent Tribe use?",
         "MATCH (:Group {attack_id: 'G0134'})-[:USES]->(s:Software) RETURN DISTINCT s.attack_id AS id ORDER BY id"),
    Case("tactics_of_technique", "Which tactics does Valid Accounts (T1078) belong to?",
         "MATCH (:Technique {attack_id: 'T1078'})-[:IN_TACTIC]->(x:Tactic) RETURN DISTINCT x.attack_id AS id ORDER BY id"),
    Case("cwes_exploited_by_capec_66", "Which weaknesses does CAPEC-66 exploit?",
         "MATCH (:CAPEC {capec_id: 'CAPEC-66'})-[:EXPLOITS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id"),
    Case("kev_cves_for_cwe_89", "Which actively exploited (KEV) CVEs have the weakness CWE-89?",
         "MATCH (v:CVE {kev: true})-[:HAS_WEAKNESS]->(:CWE {cwe_id: 'CWE-89'}) RETURN DISTINCT v.cve_id AS id ORDER BY id"),
    # The playbook uses APT29, whose 235 KEV CVEs are too many to list; Andariel's 34 can be checked completely.
    Case("full_chain_to_kev_cves", "Which actively exploited (KEV) CVEs are weakness-linked, through CAPEC patterns, to techniques used by Andariel?",
         "MATCH (:Group {attack_id: 'G0138'})-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)<-[:HAS_WEAKNESS]-(v:CVE {kev: true}) RETURN DISTINCT v.cve_id AS id ORDER BY id"),
    Case("groups_sharing_techniques", "Which groups share at least 21 techniques with APT29?",
         "MATCH (:Group {attack_id: 'G0016'})-[:USES]->(t:Technique)<-[:USES]-(o:Group) WHERE o.attack_id <> 'G0016' "
         "WITH o, count(DISTINCT t) AS c WHERE c >= 21 RETURN o.attack_id AS id ORDER BY id"),
    Case("most_used_techniques", "Which 5 techniques are used by the most groups?",
         "MATCH (g:Group)-[:USES]->(t:Technique) RETURN t.attack_id AS id, count(DISTINCT g) AS value ORDER BY value DESC, id LIMIT 5", "ranked_list"),
]


def expected(driver: Any, case: Case, n: int) -> GoldQuestion:
    with driver.session() as s:
        ids = [r["id"] for r in s.run(case.cypher)]
    # model_construct skips validation on purpose: these are not gold-set questions, and the APT29 case has 66
    # answers (the gold set caps lists at 60) to exercise long answers.
    return GoldQuestion.model_construct(id=f"q{n:03d}", question=case.question, type="aggregation" if case.style == "ranked_list" else "single_hop",
                                        hops=1, answer_style=case.style, gold_ids=ids, gold_values=[], gold_cypher=" ".join(case.cypher.split()), split="dev",
                                        precondition_cypher=None, tags=[], notes="")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the agent on the 10 sanity questions.")
    parser.add_argument("--llm-chain", default="groq-120b")
    parser.add_argument("--toolbox", choices=["mcp", "direct"], default="mcp")
    args = parser.parse_args()
    logging.basicConfig(level=logging.WARNING)
    get_settings()
    driver = get_driver()
    cases = [expected(driver, c, i) for i, c in enumerate(CASES, start=1)]
    _, chain = resolve_chain(args.llm_chain)
    toolbox: Toolbox
    if args.toolbox == "mcp":
        toolbox = McpToolbox()
    else:
        model = load_model()
        toolbox = DirectToolbox(tools.Context(driver=driver, embed=lambda t: embed_query(model, t)))
    agent = Agent(LLMClient(models=chain), toolbox, AgentConfig(), fewshot=text2cypher.build_fewshot(load_gold()))
    passed = 0
    print(f"{'#':>2} {'ok':3} {'F1':>5} {'route':8} {'pattern':9} {'tools':>5} {'llm':>3} {'tokens':>6}  question")
    try:
        for i, (case, gold) in enumerate(zip(CASES, cases, strict=True), start=1):
            r = agent.run(case.question)
            score = score_question(gold, r.answer)
            cited_ok = bool(r.citations) and all(c in r.citations for c in score["predicted"] if c in gold.gold_ids)
            ok = score["correct"] and cited_ok and r.verdict == "pass"
            passed += ok
            print(f"{i:>2} {'OK' if ok else 'BAD':3} {score['f1']:5.2f} {r.route:8} {r.pattern or '-':9} {r.tool_calls:>5} {r.llm_calls:>3} {r.tokens:>6}  {case.question[:70]}")
            if not ok:
                print(f"     verdict={r.verdict} predicted={score['predicted'][:8]} gold={gold.gold_ids[:8]} caveats={r.caveats}")
    finally:
        agent.close()
        driver.close()
    print(f"\n{passed}/{len(CASES)} sanity questions answered correctly with citations ({', '.join(args.llm_chain.split(','))}).")
    raise SystemExit(0 if passed == len(CASES) else 1)


if __name__ == "__main__":
    main()
