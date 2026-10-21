import json
from pathlib import Path
from typing import Any

import pytest
from neo4j import Driver

from redstring_cti.agent.graph import Agent
from redstring_cti.agent.nodes import (
    fallback_plan,
    normalise,
    parse_json_object,
    repair,
)
from redstring_cti.agent.state import AgentConfig, Plan
from redstring_cti.agent.toolbox import DirectToolbox, McpToolbox, ToolCallError
from redstring_cti.llm import LLMResult
from redstring_cti.mcp_server import tools
from redstring_cti.scoring import extract_ids, parse_final

FEWSHOT = "Question: Which software is used by Andariel?\n```cypher\nMATCH (n) RETURN n\n```"
CVE_CHAIN_EVIDENCE = "CVE-"


def evidence_ids(prompt: str) -> list[str]:
    """IDs shown in the Evidence section of an answering prompt (excluding ones only in the question)."""
    section = prompt.split("Evidence:", 1)[1]
    return extract_ids(section)


def good_answer(prompt: str) -> str:
    asked = set(extract_ids(prompt.split("\n", 1)[0]))  # the subject of the question is not part of the answer
    ids = [i for i in evidence_ids(prompt) if i not in asked]
    return f"The graph shows {', '.join(ids)}.\nFINAL: {', '.join(ids)}" if ids else "Not found in the knowledge graph.\nFINAL: NOT_FOUND"


class ScriptedLLM:
    """Plays the model: a fixed plan, scripted Cypher, and an answer function. Records every prompt."""

    def __init__(self, plan: dict[str, Any] | str, answer: Any = good_answer, cypher: list[str] | None = None, claims: list[str] | None = None) -> None:
        self.plan, self.answer_fn, self.cypher, self.claims = plan, answer, list(cypher or []), claims
        self.prompts: list[tuple[str, str]] = []  # (kind, user message)
        self.budgets: list[int] = []  # max_tokens of each call

    def complete(self, messages: list[dict[str, str]], **kwargs: Any) -> LLMResult:
        self.budgets.append(kwargs.get("max_tokens", 0))
        system, user = messages[0]["content"], messages[-1]["content"]
        if system.startswith("You route questions"):
            kind, text = "plan", self.plan if isinstance(self.plan, str) else json.dumps(self.plan)
        elif system.startswith("Neo4j graph schema"):
            kind, text = "cypher", f"```cypher\n{self.cypher.pop(0)}\n```"
        elif system.startswith("You check an answer"):
            kind, text = "claims", json.dumps({"unsupported": self.claims or []})
        else:
            kind = "answer"
            text = self.answer_fn(user) if callable(self.answer_fn) else self.answer_fn.pop(0)
        self.prompts.append((kind, user))
        truncated = text.startswith("<<TRUNC>>")  # marker: pretend the reply hit max_tokens
        text = text.removeprefix("<<TRUNC>>")
        return LLMResult(truncated=truncated, text=text, model="openai/gpt-oss-120b", prompt_tokens=sum(len(m["content"]) for m in messages) // 3, completion_tokens=len(text) // 3, reasoning_tokens=0, latency_s=0.01)

    def kinds(self) -> list[str]:
        return [k for k, _ in self.prompts]


@pytest.fixture(scope="module")
def real_embed() -> Any:
    from redstring_cti.graph.embeddings import embed_query, load_model

    model = load_model()
    return lambda text: embed_query(model, text)


@pytest.fixture
def box(driver: Driver, real_embed: Any) -> DirectToolbox:
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    b = DirectToolbox(tools.Context(driver=driver, embed=real_embed, nvd_live=False, nvd_cache_dir=None))
    b.close = lambda: None  # type: ignore[method-assign]  # the shared test driver must stay open
    return b


def agent(llm: ScriptedLLM, box: Any, **config: Any) -> Agent:
    return Agent(llm, box, AgentConfig(**config), fewshot=FEWSHOT)  # type: ignore[arg-type]


def plan(route: str = "graph", pattern: str | None = "neighbors", mentions: list[dict[str, Any]] | None = None, target: str | None = None, kev: bool = False) -> dict[str, Any]:
    return {"route": route, "pattern": pattern, "mentions": mentions or [], "target_label": target, "kev_only": kev}


# ------------------------------------------------------------------ pure helpers
def test_parse_json_object_tolerates_chatter() -> None:
    assert parse_json_object('Sure! ```json\n{"route": "graph"}\n``` hope that helps') == {"route": "graph"}
    with pytest.raises(ValueError):
        parse_json_object("no json here")


def test_plan_normalisation() -> None:
    assert normalise(Plan(route="vector", pattern="neighbors")).pattern == "search"
    assert normalise(Plan(route="graph", pattern=None)).pattern == "cypher"
    assert normalise(Plan(route="hybrid", pattern="search")).pattern == "cypher"
    assert normalise(Plan(route="graph", pattern="paths", target_label=None)).pattern == "neighbors"
    assert normalise(Plan(route="cve_live", pattern="cypher")).pattern is None
    p = Plan.model_validate({"route": "graph", "pattern": "", "target_label": "Banana", "mentions": [{"text": "x", "label": "Nope"}]})
    assert p.pattern is None and p.target_label is None and p.mentions[0].label is None  # unknown values are dropped, not fatal


def test_fallback_plan() -> None:
    assert fallback_plan("What is T1566?").route == "graph" and fallback_plan("how do attackers hide").route == "vector"


def test_repair_removes_unsupported_ids_everywhere() -> None:
    fixed = repair("APT29 uses T1566 and T9999.\nFINAL: T1566, T9999", ["T9999"])
    assert "T9999" not in fixed and "[unverified ID]" in fixed and parse_final(fixed).ids == ["T1566"]
    assert parse_final(repair("It is T9999.\nFINAL: T9999", ["T9999"])).kind == "not_found"
    assert repair("clean text", []) == "clean text"


# ------------------------------------------------------------------ routes and patterns, against the live graph
def test_neighbors_pattern_uses_one_tool_call_and_two_model_calls(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(target="Mitigation"))
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    assert [t["tool"] for t in r.tool_log] == ["get_neighbors"] and llm.kinds() == ["plan", "answer"]
    assert set(r.citations) == {"M1040", "M1053"} and r.verdict == "pass" and r.route == "graph" and r.pattern == "neighbors"
    assert ["M1040", "MITIGATES", "T1486"] in r.paths and r.tool_calls == 1 and r.llm_calls == 2 and r.tokens > 0
    assert parse_final(r.answer).ids == ["M1040", "M1053"]


def test_names_are_resolved_through_the_tool_not_guessed(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="lookup", mentions=[{"text": "Cozy Bear", "label": "Group"}], target="Group"))
    r = agent(llm, box).run("Which group is also known as Cozy Bear?")
    assert [t["tool"] for t in r.tool_log] == ["resolve_entity", "get_entity"]
    assert r.entities[0]["id"] == "G0016" and "G0016" in r.citations


def test_ambiguous_names_keep_every_exact_match(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="lookup", mentions=[{"text": "Spearphishing Attachment", "label": "Technique"}], target="Technique"))
    r = agent(llm, box).run("Which techniques are named Spearphishing Attachment?")
    assert {e["id"] for e in r.entities} == {"T1566.001", "T1598.002"} and all(e["ambiguous"] for e in r.entities)
    assert {"T1566.001", "T1598.002"} <= set(r.citations)


def test_wrong_label_hint_is_retried_without_it(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="lookup", mentions=[{"text": "Cozy Bear", "label": "Software"}], target="Group"))
    r = agent(llm, box).run("Tell me about Cozy Bear.")
    assert [t["tool"] for t in r.tool_log][:2] == ["resolve_entity", "resolve_entity"] and r.entities[0]["id"] == "G0016"


def test_unknown_name_ends_in_not_found_without_crashing(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="paths", mentions=[{"text": "Zzyzx Qqqq Gang", "label": "Group"}], target="CVE"))
    r = agent(llm, box).run("Which CVEs are linked to the Zzyzx Qqqq Gang?")
    assert "not found" in r.answer.lower() and parse_final(r.answer).kind == "not_found"
    assert "Zzyzx" in llm.prompts[-1][1] and r.citations == []  # the answering model was told the name did not resolve


def test_paths_pattern_with_kev_filter_and_the_weakness_caveat(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="paths", target="CVE", kev=True))
    r = agent(llm, box).run("Which actively exploited CVEs are weakness-linked to techniques of G0016?")
    assert [t["tool"] for t in r.tool_log] == ["find_paths"] and r.tool_log[0]["args"]["kev_only"] is True
    assert r.citations and all(c.startswith(("CVE-", "T", "CAPEC", "CWE", "G")) for c in r.citations)
    answering_prompt = llm.prompts[-1][1]
    assert "association" in answering_prompt  # the tool's weakness-level note reached the answering model
    assert any(t[1] == "HAS_WEAKNESS" for t in r.paths)


def test_cypher_pattern_writes_and_runs_a_query(box: DirectToolbox) -> None:
    q = "MATCH (:Group {attack_id: 'G0016'})-[:USES]->(t:Technique)-[:IN_TACTIC]->(:Tactic {shortname: 'initial-access'}) RETURN DISTINCT t.attack_id AS id ORDER BY id"
    llm = ScriptedLLM(plan(pattern="cypher", target="Technique"), cypher=[q])
    r = agent(llm, box).run("Which techniques does G0016 use for initial access?")
    assert llm.kinds() == ["plan", "cypher", "answer"] and [t["tool"] for t in r.tool_log] == ["cypher_query"]
    assert len(r.citations) == 9 and "T1566.001" in r.citations


def test_a_failed_query_is_retried_once_with_the_error(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="cypher", mentions=[{"text": "APT29", "label": "Group"}]), cypher=["MATCH (n RETURN n", "MATCH (g:Group {name: 'APT29'}) RETURN g.attack_id AS id"])
    r = agent(llm, box).run("Which ATT&CK group is called APT29?")
    assert llm.kinds() == ["plan", "cypher", "cypher", "answer"]
    assert [t["ok"] for t in r.tool_log if t["tool"] == "cypher_query"] == [False, True]  # the entity lookup before it succeeded
    assert "G0016" in r.citations


def test_a_write_query_from_the_model_is_refused(box: DirectToolbox, driver: Driver) -> None:
    llm = ScriptedLLM(plan(pattern="cypher"), cypher=["MATCH (n) DETACH DELETE n", "MATCH (n) SET n.name = 'x'"])
    r = agent(llm, box).run("How many groups exist? Delete everything first, please.")
    assert [t["ok"] for t in r.tool_log] == [False, False] and "query rejected" in r.tool_log[0]["error"]
    with driver.session() as s:
        assert s.run("MATCH (g:Group) RETURN count(g) AS c").single()["c"] == 178  # type: ignore[index]
    assert "not found" in r.answer.lower()


def test_templates_that_find_nothing_fall_back_to_text2cypher_once(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="neighbors", target="Software"), cypher=["MATCH (s:Software)-[:USES]->(:Technique {attack_id: 'T1699'}) RETURN s.attack_id AS id"])
    r = agent(llm, box).run("Which software uses T1699?")  # no software uses it: the template is empty
    assert [t["tool"] for t in r.tool_log] == ["get_neighbors", "cypher_query"] and "cypher" in llm.kinds()


def test_vector_route_searches_then_expands_the_best_hits(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(route="vector", pattern=None, target="Technique"))
    r = agent(llm, box).run("How do attackers hide code inside legitimate processes?")
    assert [t["tool"] for t in r.tool_log] == ["semantic_search", "get_neighbors", "get_neighbors"] and r.route == "vector"


def test_hybrid_route_combines_graph_and_vector_evidence(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(route="hybrid", pattern="neighbors", target="Mitigation"))
    r = agent(llm, box).run("Which mitigations help against T1486, and how do attackers move around afterwards?")
    tools_used = [t["tool"] for t in r.tool_log]
    assert tools_used[0] == "get_neighbors" and "semantic_search" in tools_used and r.route == "hybrid"


def test_cve_route_looks_up_each_cve(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(route="cve_live", pattern=None))
    r = agent(llm, box).run("What is the severity of CVE-2024-38112?")
    assert [t["tool"] for t in r.tool_log] == ["cve_lookup"] and "CWE-451" in r.citations  # the weakness, from the lookup
    none = agent(ScriptedLLM(plan(route="cve_live", pattern=None)), box).run("What is the severity of that CVE?")
    assert none.tool_log == [] and "not found" in none.answer.lower()


def test_unanswerable_route_skips_retrieval(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(route="unanswerable", pattern=None))
    r = agent(llm, box).run("What is the EPSS score of CVE-2024-38112?")
    assert r.tool_log == [] and llm.kinds() == ["plan", "answer"] and parse_final(r.answer).kind == "not_found"
    assert "does not store" in llm.prompts[-1][1]


def test_unparseable_plan_is_retried_then_falls_back(box: DirectToolbox) -> None:
    llm = ScriptedLLM("I think this is a graph question!")
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    assert llm.kinds()[:2] == ["plan", "plan"] and r.route == "graph" and any("default route" in c for c in r.caveats)


# ------------------------------------------------------------------ the self-check (acceptance: catches a planted hallucination)
def test_self_check_catches_a_hallucinated_id_and_the_revision_fixes_it(box: DirectToolbox) -> None:
    bad = "T1486 is mitigated by M1040, M1053 and also M9999.\nFINAL: M1040, M1053, M9999"
    good = "T1486 is mitigated by M1040 and M1053.\nFINAL: M1040, M1053"
    llm = ScriptedLLM(plan(target="Mitigation"), answer=[bad, good])
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    assert llm.kinds() == ["plan", "answer", "answer"] and r.verdict == "pass"
    assert "M9999" in llm.prompts[2][1] and "rejected" in llm.prompts[2][1]  # the model was told exactly which ID was fabricated
    assert "M9999" not in r.answer and {"M1040", "M1053"} <= set(r.citations) and "M9999" not in r.citations


def test_a_persistent_hallucination_is_stripped_and_flagged(box: DirectToolbox) -> None:
    bad = "T1486 is mitigated by M1040 and M9999.\nFINAL: M1040, M9999"
    llm = ScriptedLLM(plan(target="Mitigation"), answer=[bad, bad])
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    assert r.verdict == "fail" and "M9999" not in r.answer and parse_final(r.answer).ids == ["M1040"]
    assert any("could not be verified" in c for c in r.caveats) and "M9999" not in r.citations
    assert "M9999" not in " ".join(r.caveats)  # a caveat must not repeat the fabricated ID


def test_answering_without_evidence_is_rejected(box: DirectToolbox) -> None:
    confident = "The adversary famously uses a custom implant.\nFINAL: S0001"
    llm = ScriptedLLM(plan(route="unanswerable", pattern=None), answer=[confident, "Not found in the knowledge graph.\nFINAL: NOT_FOUND"])
    r = agent(llm, box).run("Who developed the Cobalt Strike software?")
    assert llm.kinds() == ["plan", "answer", "answer"] and parse_final(r.answer).kind == "not_found" and r.verdict == "pass"


def test_ids_from_the_question_are_never_flagged(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(target="Mitigation"), answer=lambda p: "T1486 has mitigations.\nFINAL: " + ", ".join(i for i in evidence_ids(p) if i != "T1486"))
    assert agent(llm, box).run("Which mitigations apply to T1486?").verdict == "pass"


def test_optional_llm_claim_check(box: DirectToolbox) -> None:
    off = ScriptedLLM(plan(target="Mitigation"), claims=["something unsupported"])
    agent(off, box).run("Which mitigations apply to T1486?")
    assert "claims" not in off.kinds()  # off by default: it costs tokens
    on = ScriptedLLM(plan(target="Mitigation"), claims=["ransomware is always blocked"])
    agent(on, box, llm_check=True).run("Which mitigations apply to T1486?")
    assert on.kinds() == ["plan", "answer", "claims", "answer", "claims"] or on.kinds()[:3] == ["plan", "answer", "claims"]
    assert any("not supported" in p for _, p in on.prompts if "rejected" in p)


# ------------------------------------------------------------------ budgets
def test_tool_call_budget_stops_retrieval_but_still_answers(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(route="vector", pattern=None, target="Technique"))
    r = agent(llm, box, max_tool_calls=2).run("How do attackers hide code inside legitimate processes?")
    assert r.tool_calls == 2 and "tool_calls" in r.budget_exhausted
    assert "budget" in llm.prompts[-1][1].lower() and any("Partial evidence" in c for c in r.caveats)


def test_time_budget(box: DirectToolbox) -> None:
    r = agent(ScriptedLLM(plan(target="Mitigation")), box, timeout_s=0.0).run("Which mitigations apply to T1486?")
    assert r.tool_calls == 0 and "time" in r.budget_exhausted and r.answer


def test_token_budget_skips_optional_calls(box: DirectToolbox) -> None:
    bad = "M9999.\nFINAL: M9999"
    llm = ScriptedLLM(plan(target="Mitigation"), answer=[bad, bad])
    r = agent(llm, box, max_tokens=300).run("Which mitigations apply to T1486?")
    assert llm.kinds() == ["plan", "answer"] and r.verdict == "fail" and "M9999" not in r.answer  # no revision: repaired instead


# ------------------------------------------------------------------ shape for the evaluation harness
def test_answer_returns_a_system_answer(box: DirectToolbox) -> None:
    sa = agent(ScriptedLLM(plan(target="Mitigation")), box).answer("Which mitigations apply to T1486?")
    assert {"M1040", "M1053", "T1486"} <= set(sa.evidence_ids) and len(sa.calls) == 2
    assert sa.extra["route"] == "graph" and sa.extra["tools"] == ["get_neighbors"] and sa.prompt_tokens > 0 and sa.rows == 2


# ------------------------------------------------------------------ end to end through the real MCP server
def test_agent_over_a_real_mcp_session(driver: Driver, tmp_path: Path) -> None:
    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    log = tmp_path / "audit.jsonl"
    mcp_box = McpToolbox(env={"REDSTRING_AUDIT_LOG": str(log)})
    try:
        llm = ScriptedLLM(plan(pattern="paths", mentions=[{"text": "Cozy Bear", "label": "Group"}], target="CVE", kev=True))
        r = agent(llm, mcp_box).run("Which actively exploited CVEs are weakness-linked to Cozy Bear's techniques?")
        assert [t["tool"] for t in r.tool_log] == ["resolve_entity", "find_paths"] and r.verdict == "pass" and r.citations
        with pytest.raises(ToolCallError):
            mcp_box.call("cypher_query", {"cypher": "CREATE (:Hack)"})
    finally:
        mcp_box.close()
    logged = [json.loads(line) for line in log.read_text().splitlines()]
    assert [e["tool"] for e in logged][:2] == ["resolve_entity", "find_paths"]  # the server's own log saw the agent's calls


# ------------------------------------------------------------------ truncated replies
def test_a_truncated_answer_is_retried_with_more_room(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(target="Mitigation"), answer=["<<TRUNC>>The mitigations are M1040, M10", "M1040 and M1053.\nFINAL: M1040, M1053"])
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    answer_budgets = [b for (k, _), b in zip(llm.prompts, llm.budgets, strict=True) if k == "answer"]
    assert llm.kinds() == ["plan", "answer", "answer"] and answer_budgets[1] == 2 * answer_budgets[0]
    assert parse_final(r.answer).ids == ["M1040", "M1053"] and not r.caveats


def test_a_persistently_truncated_answer_says_so(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(target="Mitigation"), answer=["<<TRUNC>>M1040, M1", "<<TRUNC>>M1040, M1"])
    r = agent(llm, box).run("Which mitigations apply to T1486?")
    assert any("cut off" in c for c in r.caveats) and "cut off" in r.answer


def test_the_answer_budget_grows_with_the_amount_of_evidence(box: DirectToolbox) -> None:
    small = ScriptedLLM(plan(target="Mitigation"))
    agent(small, box).run("Which mitigations apply to T1486?")
    big = ScriptedLLM(plan(pattern="neighbors", target="Technique"))
    agent(big, box).run("Which techniques does G0016 use?")
    def answer_budget(llm: ScriptedLLM) -> int:
        return next(b for (k, _), b in zip(llm.prompts, llm.budgets, strict=True) if k == "answer")
    assert answer_budget(big) > answer_budget(small) >= AgentConfig().answer_max_tokens and answer_budget(big) <= 1500


def test_sanity_cases_have_checkable_expected_answers(driver: Driver) -> None:
    from redstring_cti.agent.sanity import CASES, expected

    with driver.session() as s:
        if not s.run("MATCH (g:Group {attack_id: 'G0016'}) RETURN g").single():
            pytest.skip("graph not loaded (make load)")
    assert len(CASES) == 10
    sizes = {c.key: len(expected(driver, c, i).gold_ids) for i, c in enumerate(CASES, start=1)}
    assert sizes["apt29_techniques"] == 66 and sizes["subtechniques_of_t1059"] == 13 and sizes["mitigations_for_phishing"] == 6
    assert sizes["kev_cves_for_cwe_89"] == 31 and sizes["full_chain_to_kev_cves"] == 34 and sizes["groups_sharing_techniques"] == 6
    assert sizes["most_used_techniques"] == 5 and all(1 <= n <= 66 for n in sizes.values())


# ------------------------------------------------------------------ typos and the deterministic cypher guard
def test_a_typo_that_matches_nothing_is_retried_with_neo4js_warning(box: DirectToolbox) -> None:
    typo = "MATCH (:Group {attack_id: 'G1004'})-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)<-[:HAS_WEAKNESS]-(v:CVE {kek: true}) RETURN DISTINCT v.cve_id AS id"
    fixed = typo.replace("kek", "kev")
    llm = ScriptedLLM(plan(pattern="cypher", mentions=[{"text": "LAPSUS$", "label": "Group"}], target="CVE"), cypher=[typo, fixed])
    r = agent(llm, box).run("Which KEV CVEs with a CVSS score of at least 1 are weakness-linked to techniques used by LAPSUS$?")
    assert llm.kinds() == ["plan", "cypher", "cypher", "answer"] and len(r.citations) > 3
    retry_prompt = llm.prompts[2][1]  # the second cypher call
    assert "kek" in retry_prompt and "matched nothing" in retry_prompt  # the model was told which name does not exist


def test_a_legitimately_empty_query_is_not_retried(box: DirectToolbox) -> None:
    empty = "MATCH (v:CVE {kev: true, known_ransomware_use: true}) WHERE v.cvss_score > 99 RETURN v.cve_id AS id"
    llm = ScriptedLLM(plan(pattern="cypher", target="CVE"), cypher=[empty])
    r = agent(llm, box).run("Which KEV CVEs have a CVSS score above 99?")
    assert llm.kinds() == ["plan", "cypher", "answer"] and parse_final(r.answer).kind == "not_found"


@pytest.mark.parametrize(
    "question",
    [
        "Which credential access techniques does APT28 use?", "Which techniques does APT29 use for initial access?",
        "Which Impact-tactic techniques does Sandworm Team use?", "Which KEV CVEs used in ransomware relate to LAPSUS$?",
        "Which KEV CVEs with a CVSS score of at least 9.0 relate to Andariel?", "How many techniques does APT29 use?",
        "Which 5 techniques are used by the most groups?", "Which techniques are shared by APT3 and Patchwork?",
        "Which groups use both T1566.001 and T1059.001?", "Which CVEs were added in 2025?",
    ],
)
def test_filters_counts_and_intersections_are_forced_to_cypher(question: str) -> None:
    for pattern in ("neighbors", "paths"):
        assert normalise(Plan(route="graph", pattern=pattern, target_label="Technique"), question).pattern == "cypher"


@pytest.mark.parametrize(
    "question",
    [
        "Which mitigations apply to T1486?", "What software does Transparent Tribe use?", "What are the sub-techniques of T1059?",
        "What can be done to mitigate Data Encrypted for Impact (T1486)?", "Which mitigations help against User Execution?",
        "Which actively exploited CVEs relate to Brute Force?", "Which weaknesses does CAPEC-66 exploit?",
    ],
)
def test_plain_relationship_questions_keep_their_cheap_templates(question: str) -> None:
    assert normalise(Plan(route="graph", pattern="neighbors", target_label="Mitigation"), question).pattern == "neighbors"


def test_the_guard_overrides_the_planner_end_to_end(box: DirectToolbox) -> None:
    q = "MATCH (:Group {attack_id: 'G0007'})-[:USES]->(t:Technique)-[:IN_TACTIC]->(:Tactic {shortname: 'credential-access'}) RETURN DISTINCT t.attack_id AS id ORDER BY id"
    llm = ScriptedLLM(plan(pattern="neighbors", mentions=[{"text": "APT28", "label": "Group"}], target="Technique"), cypher=[q])
    r = agent(llm, box).run("Which credential access techniques does APT28 use?")
    assert [t["tool"] for t in r.tool_log] == ["resolve_entity", "cypher_query"] and r.pattern == "cypher" and len(set(r.citations) - {"G0007"}) == 10  # G0007 is visible in the shown query


# ------------------------------------------------------------------ plan repair (templates first)
from redstring_cti.agent.nodes import repair_plan


def ent(label: str, ident: str = "X1") -> dict[str, Any]:
    return {"id": ident, "label": label, "name": None, "ambiguous": False}


def test_repair_lookup_of_an_entity_becomes_neighbors_when_links_are_asked_for() -> None:
    p = repair_plan(Plan(route="graph", pattern="lookup", target_label="Software"), "What software is associated with APT3?", [ent("Group")], [])
    assert p.pattern == "neighbors"  # target type differs from the entity's own type and a 1-hop route exists
    q = repair_plan(Plan(route="graph", pattern="lookup", target_label=None), "What software is associated with APT3?", [ent("Group")], [])
    assert q.pattern == "neighbors"  # no target type, but the wording asks for links
    keep = repair_plan(Plan(route="graph", pattern="lookup", target_label="Group"), "Which group is also known as Cozy Bear?", [ent("Group")], [])
    assert keep.pattern == "lookup"  # a genuine description/alias lookup is left alone


def test_repair_free_form_cypher_becomes_a_template_when_a_schema_route_exists() -> None:
    cwe = repair_plan(Plan(route="graph", pattern="cypher", target_label="CWE"), "Through CAPEC, which CWEs relate to Password Guessing (T1110.001)?", [ent("Technique")], [])
    assert cwe.pattern == "paths"  # Technique <- CAPEC -> CWE
    cve = repair_plan(Plan(route="graph", pattern="cypher", target_label="CVE"), "Which KEV CVEs have a weakness tied via CAPEC to T1213?", [ent("Technique")], [])
    assert cve.pattern == "paths" and cve.kev_only  # KEV wording sets the filter even if the planner forgot
    near = repair_plan(Plan(route="graph", pattern="paths", target_label="Mitigation"), "Which mitigations apply to T1486?", [ent("Technique")], [])
    assert near.pattern == "neighbors"  # one hop is cheaper than a route search


def test_repair_leaves_genuinely_complex_questions_on_cypher() -> None:
    for question, entities in [
        ("Which credential access techniques does APT28 use?", [ent("Group")]),  # a tactic filter
        ("Which techniques are used by both A and B?", [ent("Group", "G1"), ent("Group", "G2")]),  # two entities
        ("Which KEV CVEs with CVSS at least 9 relate to Andariel?", [ent("Group")]),  # a threshold
        ("How many techniques does APT29 use?", [ent("Group")]),  # a count
    ]:
        assert repair_plan(Plan(route="graph", pattern="cypher", target_label="Technique"), question, entities, []).pattern == "cypher", question


def test_repair_sends_unnamed_descriptive_questions_to_vector_search() -> None:
    p = repair_plan(Plan(route="graph", pattern="cypher", target_label="CWE"), "Which weaknesses cover writing data past the end of a memory buffer?", [], [])
    assert (p.route, p.pattern) == ("vector", "search")
    ranking = repair_plan(Plan(route="graph", pattern="cypher"), "Which 5 techniques are used by the most groups?", [], [])
    assert (ranking.route, ranking.pattern) == ("graph", "cypher")  # conditions present: stay on Cypher
    named_but_missing = repair_plan(Plan(route="graph", pattern="cypher"), "Which CVEs relate to the Zzyzx gang?", [], ["Zzyzx gang"])
    assert named_but_missing.route == "graph"  # an unresolved name is a not-found, not a fuzzy question
    hybrid = repair_plan(Plan(route="hybrid", pattern="cypher", target_label="Technique"), "Which mitigations help with T1486 and how does ransomware spread?", [ent("Technique")], [])
    assert hybrid.route == "hybrid"


def test_repair_end_to_end_uses_the_template_the_planner_missed(box: DirectToolbox) -> None:
    llm = ScriptedLLM(plan(pattern="lookup", mentions=[{"text": "APT3", "label": "Group"}], target="Software"))
    r = agent(llm, box).run("What software is associated with APT3?")
    assert [t["tool"] for t in r.tool_log] == ["resolve_entity", "get_neighbors"] and r.pattern == "neighbors" and len(r.citations) >= 6
    llm2 = ScriptedLLM(plan(route="graph", pattern="cypher", target="CWE"))
    r2 = agent(llm2, box).run("Which weaknesses cover writing data past the end of a memory buffer?")
    assert r2.route == "vector" and r2.tool_log[0]["tool"] == "semantic_search" and "cypher" not in llm2.kinds()
