"""The agent's graph nodes. Deterministic work (IDs, entity resolution, template tool calls, the
citation check) is plain code; the model is used only to plan, to write Cypher when no template fits,
and to write the final answer."""

import json
import re
from typing import Any

from pydantic import ValidationError

from redstring_cti.agent import evidence as ev
from redstring_cti.agent.prompts import (
    ANSWER_SYSTEM,
    CLAIM_CHECK_SYSTEM,
    PLAN_SYSTEM,
    REVISE_NOTE,
)
from redstring_cti.agent.state import AgentState, BudgetExceeded, Plan, Run
from redstring_cti.agent.toolbox import ToolCallError
from redstring_cti.graph.ids import parse_id
from redstring_cti.graph.metapaths import enumerate_metapaths
from redstring_cti.retrieval import text2cypher
from redstring_cti.scoring import extract_ids, parse_final

MAX_MENTIONS = 4
MAX_ENTITIES = 6
ENTITY_PATTERNS = ("lookup", "neighbors", "paths")


def parse_json_object(text: str) -> dict[str, Any]:
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in the reply")
    return dict(json.loads(text[start : end + 1]))


def fallback_plan(question: str) -> Plan:
    """If the model's plan cannot be parsed twice: IDs in the question mean graph, otherwise vector."""
    ids = extract_ids(question)
    if ids:
        return Plan(route="graph", pattern="neighbors" if len(ids) == 1 else "cypher")
    return Plan(route="vector", pattern="search")


_TACTICS = (
    "initial access|persistence|privilege escalation|defen[cs]e evasion|defen[cs]e impairment|stealth|credential access|discovery|"
    "lateral movement|collection|command and control|exfiltration|impact|execution|reconnaissance|resource development"
)
# Cues that a question needs conditions, aggregation or an intersection: only Cypher can express them.
NEEDS_CYPHER = re.compile(
    # a tactic in a tactic role: "credential access techniques", "Impact-tactic", "for initial access" (but not "Data Encrypted for Impact (T1486)")
    rf"\b(?:{_TACTICS})\b[- ]*(?:tactic\b|techniques?\b)|\b(?:for|in|during|within) (?:the )?(?:{_TACTICS})\b(?! \()|"
    r"ransomware|cvss|\bscores?\b|severity|at least|at most|more than|fewer than|greater|higher than|lower than|"
    r"\b(?:since|after|before|during|in) (?:19|20)\d\d|how many|number of|\bcount\b|\btop \d+|\d+ (?:most|least)|\bmost\b|\bleast\b|"
    r"\bhighest\b|\blowest\b|\bboth\b|in common|\bshared?\b|\bsharing\b|\bintersect",
    re.IGNORECASE,
)


KEV_WORDS = re.compile(r"\bKEV\b|actively exploited|known[- ]exploited|exploited in the wild", re.IGNORECASE)
RELATION_CUES = re.compile(r"\b(?:uses?|used|associated|related|linked|mitigat\w*|sub-?techniques?|attributed)\b", re.IGNORECASE)


def repair_plan(plan: Plan, question: str, entities: list[dict[str, Any]], unresolved: list[str]) -> Plan:
    """Deterministic corrections for the planner's most common mistakes, applied once the entities are known.

    Principle (from the playbook): templates first, free-form Cypher only when no template fits. A small model
    often writes Cypher, or a plain lookup, where a template (neighbors / find_paths) answers exactly."""
    if plan.route not in ("graph", "hybrid"):
        return plan
    cue = bool(NEEDS_CYPHER.search(question))
    if plan.target_label == "CVE" and KEV_WORDS.search(question):
        plan.kev_only = True
    # Nothing named and no condition to express: a fuzzy description, which vector search handles best.
    if plan.route == "graph" and not entities and not unresolved and not cue and plan.pattern in ("cypher", "lookup", "neighbors", "paths"):
        plan.route, plan.pattern = "vector", "search"
        return plan
    if cue or len(entities) != 1:
        return plan
    label = entities[0]["label"]
    target = plan.target_label
    if target and target != label:
        routes = enumerate_metapaths(label, target)
        if routes:  # a schema route exists: use the template that follows it
            plan.pattern = "neighbors" if routes[0].hops == 1 else "paths"
    elif plan.pattern == "lookup" and RELATION_CUES.search(question):
        plan.pattern = "neighbors"  # "what software is associated with X" asks for links, not X's own properties
    return plan


def normalise(plan: Plan, question: str = "") -> Plan:
    """Make route and pattern consistent (models sometimes leave one blank) and enforce a deterministic rule:
    templates (neighbors, paths) cannot express filters, counts or intersections, so such questions use Cypher."""
    if plan.route == "vector":
        plan.pattern = "search"
    elif plan.route in ("graph", "hybrid"):
        if plan.pattern in (None, "search"):
            plan.pattern = "cypher"
        if plan.pattern == "paths" and plan.target_label is None:
            plan.pattern = "neighbors"
    else:
        plan.pattern = None
    if plan.route in ("graph", "hybrid") and plan.pattern in ("neighbors", "paths") and NEEDS_CYPHER.search(question):
        plan.pattern = "cypher"
    return plan


def repair(text: str, unsupported: list[str]) -> str:
    """Last resort when a revision still cites IDs that were never retrieved: remove them."""
    if not unsupported:
        return text
    for bad in unsupported:
        text = re.sub(rf"\b{re.escape(bad)}\b", "[unverified ID]", text)
    final = parse_final(text)
    lines = text.splitlines()
    if final.kind == "none" and not any(line.strip().upper().startswith("FINAL") for line in lines):
        return text
    kept = [i for i in final.ids if i != "[unverified ID]"]
    new_final = "FINAL: " + ", ".join(kept) if kept else "FINAL: NOT_FOUND"
    out = [line for line in lines if not line.strip().lstrip("*").upper().startswith("FINAL")]
    return "\n".join([*out, new_final]).strip()


class AgentNodes:
    def __init__(self, fewshot: str) -> None:
        self.fewshot = fewshot

    # ------------------------------------------------------------------ plan
    def plan_route(self, state: AgentState) -> dict[str, Any]:
        run, question = state["run"], state["question"]
        messages = [{"role": "system", "content": PLAN_SYSTEM}, {"role": "user", "content": f"Q: {question}"}]
        plan: Plan | None = None
        for attempt in range(2):
            result = run.complete(messages, max_tokens=run.config.plan_max_tokens, optional=attempt > 0)
            if result is None:
                break
            try:
                plan = Plan.model_validate(parse_json_object(result.text))
                break
            except (ValueError, ValidationError):
                messages = [*messages, {"role": "assistant", "content": result.text},
                            {"role": "user", "content": "That was not valid. Reply with the JSON object only."}]
        used_fallback = plan is None
        plan = normalise(plan or fallback_plan(question), question)
        return {"plan": plan.model_dump(), "route": plan.route, "pattern": plan.pattern,
                "caveats": ["The question could not be routed by the model; a default route was used."] if used_fallback else []}

    # ------------------------------------------------------------------ entities
    def resolve_entities(self, state: AgentState) -> dict[str, Any]:
        run, plan = state["run"], Plan.model_validate(state["plan"])
        entities: dict[str, dict[str, Any]] = {}
        for found in extract_ids(state["question"]):
            ref = parse_id(found)
            if ref:
                entities[ref.key] = {"id": ref.key, "label": ref.label, "name": None, "ambiguous": False}
        unresolved: list[str] = []
        for mention in plan.mentions[:MAX_MENTIONS]:
            if parse_id(mention.text):
                continue
            picked = self._resolve_one(run, mention.text, mention.label)
            if not picked:
                unresolved.append(mention.text)
            for c in picked:
                entities.setdefault(c["id"], {"id": c["id"], "label": c["label"], "name": c["name"], "ambiguous": len(picked) > 1})
        resolved = list(entities.values())[:MAX_ENTITIES]
        before = (plan.route, plan.pattern, plan.kev_only)
        plan = repair_plan(plan, state["question"], resolved, unresolved)
        update: dict[str, Any] = {"entities": resolved, "unresolved": unresolved, "tool_calls": len(run.tool_log)}
        if (plan.route, plan.pattern, plan.kev_only) != before:
            update.update(plan=plan.model_dump(), route=plan.route, pattern=plan.pattern)
        return update

    @staticmethod
    def _resolve_one(run: Run, name: str, label: str | None) -> list[dict[str, Any]]:
        for labels in ([label], None) if label else (None,):
            try:
                res = run.tool("resolve_entity", {"name": name, "labels": labels, "limit": 5})
            except (BudgetExceeded, ToolCallError):
                return []
            cands = res["candidates"]
            exact = [c for c in cands if c["exact"]]
            if exact:
                return exact[:3]
            if cands:
                top = cands[0]
                hay = f"{top['name']} {' '.join(top.get('aliases', []))}".lower()
                if all(w in hay for w in name.lower().split()):
                    return [top]
        return []

    # ------------------------------------------------------------------ retrieval
    def graph_retrieve(self, state: AgentState) -> dict[str, Any]:
        run, plan = state["run"], Plan.model_validate(state["plan"])
        pattern, entities = state.get("pattern") or "cypher", state.get("entities", [])
        gathered: list[Any] = []
        if pattern in ENTITY_PATTERNS and not entities:  # e.g. the only named entity could not be resolved
            names = ", ".join(state.get("unresolved", [])) or "the entity"
            return {"evidence": [ev.note(f"Could not find {names} in the graph, so nothing could be retrieved.")], "tool_calls": len(run.tool_log)}
        try:
            if pattern == "lookup":
                for e in entities[:3]:
                    args = {"id": e["id"]}
                    gathered.append(ev.entity(run.tool("get_entity", args), args))
            elif pattern == "neighbors":
                for e in entities[:2]:
                    args = {"id": e["id"], "limit": 200}
                    gathered.append(ev.neighbors(run.tool("get_neighbors", args), args, plan.target_label))
            elif pattern == "paths":
                e = entities[0]
                args = {"from_id": e["id"], "to_label": plan.target_label, "limit": 50, "kev_only": plan.kev_only}
                gathered.append(ev.paths(run.tool("find_paths", args), args))
            else:
                gathered.append(self._cypher(run, state))
            if pattern != "cypher" and not any(g["items"] for g in gathered) and entities and run.can_spend(plan_cost(run)):
                gathered.append(self._cypher(run, state))  # templates found nothing: one Text2Cypher attempt
        except (BudgetExceeded, ToolCallError) as exc:
            gathered.append(ev.note(f"Retrieval stopped early: {exc}"))
        return {"evidence": [g for g in gathered if g], "tool_calls": len(run.tool_log)}

    def _cypher(self, run: Run, state: AgentState) -> Any:
        known = ", ".join(f"{e.get('name') or e['label']}={e['id']}" for e in state.get("entities", []))
        messages = [
            {"role": "system", "content": f"{text2cypher.SCHEMA}\n\nExamples:\n\n{self.fewshot}"},
            {"role": "user", "content": f"Question: {state['question']}" + (f"\nKnown entity ids: {known}" if known else "")},
        ]
        last_error = "no query"
        for attempt in range(2):
            gen = run.complete(messages, max_tokens=run.config.cypher_max_tokens, optional=attempt > 0)
            if gen is None:
                break
            cypher = text2cypher.extract_cypher(gen.text)
            try:
                res = run.tool("cypher_query", {"cypher": cypher})
                if res["row_count"] == 0 and res.get("warnings") and attempt == 0:
                    raise ToolCallError("the query matched nothing; " + " ".join(res["warnings"]))  # a typo, not a real empty answer
                return ev.rows(res, {"cypher": cypher})
            except ToolCallError as exc:
                last_error = str(exc)
                messages = [*messages, {"role": "assistant", "content": gen.text},
                            {"role": "user", "content": f"That query failed: {last_error}\nReturn a corrected query in a ```cypher block."}]
        return ev.note(f"No valid query could be run ({last_error}).")

    def vector_retrieve(self, state: AgentState) -> dict[str, Any]:
        run, plan = state["run"], Plan.model_validate(state["plan"])
        gathered = []
        try:
            args: dict[str, Any] = {"query": state["question"], "labels": [plan.target_label] if plan.target_label else None, "k": 8}
            res = run.tool("semantic_search", args)
            gathered.append(ev.search(res, args))
            for hit in res["results"][:2]:  # expand the best hits one hop so relationships are visible
                nargs = {"id": hit["id"], "limit": 15}
                gathered.append(ev.neighbors(run.tool("get_neighbors", nargs), nargs, None))
        except (BudgetExceeded, ToolCallError) as exc:
            gathered.append(ev.note(f"Retrieval stopped early: {exc}"))
        return {"evidence": gathered, "tool_calls": len(run.tool_log)}

    def cve_node(self, state: AgentState) -> dict[str, Any]:
        run = state["run"]
        cves = [e for e in state.get("entities", []) if e["label"] == "CVE"][:3]
        gathered = []
        try:
            for e in cves:
                args = {"cve_id": e["id"]}
                gathered.append(ev.cve(run.tool("cve_lookup", args), args))
        except (BudgetExceeded, ToolCallError) as exc:
            gathered.append(ev.note(f"Lookup stopped early: {exc}"))
        if not cves:
            gathered.append(ev.note("The question names no CVE identifier."))
        return {"evidence": gathered, "tool_calls": len(run.tool_log)}

    # ------------------------------------------------------------------ answer and check
    def answer(self, state: AgentState) -> dict[str, Any]:
        run = state["run"]
        block, _ = ev.render(state.get("evidence", []), run.config.evidence_chars)
        notes = []
        if state.get("unresolved"):
            notes.append("These names were not found in the graph: " + ", ".join(state["unresolved"]) + ".")
        if any(e.get("ambiguous") for e in state.get("entities", [])):
            notes.append("Some names matched more than one entity; mention each if relevant.")
        if run.exhausted:
            notes.append(f"Budget limits were reached ({', '.join(run.exhausted)}); the evidence may be incomplete.")
        if state.get("route") == "unanswerable":
            notes.append("The question looks like it asks for data the graph does not store.")
        entities = ", ".join(f"{e.get('name') or ''} {e['id']} ({e['label']})".strip() for e in state.get("entities", []))
        user = f"Question: {state['question']}\n" + (f"Resolved entities: {entities}\n" if entities else "") + "\n".join(notes) + f"\n\nEvidence:\n{block}"
        if state.get("feedback"):
            user += "\n\n" + REVISE_NOTE.format(problem=state["feedback"])
        messages = [{"role": "system", "content": ANSWER_SYSTEM}, {"role": "user", "content": user}]
        shown = sum(e["items"] for e in state.get("evidence", []))
        budget = min(run.config.answer_max_tokens + 8 * shown, 1500)  # a long list needs room for its FINAL line
        result = run.complete(messages, max_tokens=budget)
        assert result is not None
        caveats: list[str] = []
        if result.truncated:  # cut off mid-answer: one retry with double the room, else say so
            retry = run.complete(messages, max_tokens=min(budget * 2, 3000), optional=True)
            if retry is not None and not retry.truncated:
                result = retry
            else:
                caveats.append("The answer was cut off by the output limit and may be incomplete.")
        return {"draft": result.text, "feedback": None, "tokens": run.tokens, "caveats": caveats}

    def self_check(self, state: AgentState) -> dict[str, Any]:
        run, text = state["run"], state["draft"] or ""
        evidence = state.get("evidence", [])
        _, visible = ev.render(evidence, run.config.evidence_chars)
        allowed = set(visible) | set(extract_ids(state["question"])) | {e["id"] for e in state.get("entities", [])}
        cited = extract_ids(text)
        unsupported = [i for i in cited if i not in allowed]
        problems = []
        if unsupported:
            problems.append(f"it cites IDs that are not in the evidence: {', '.join(unsupported)}")
        if not any(e["items"] for e in evidence) and parse_final(text).kind != "not_found":
            problems.append("it states an answer although no evidence was retrieved")
        if run.config.llm_check and not problems and evidence:
            claims = self._claim_check(run, text, evidence)
            if claims:
                problems.append("claims not supported by the evidence: " + "; ".join(claims[:3]))
        revisions = state.get("revisions", 0)
        if problems and revisions < run.config.max_revisions and run.can_spend(run.config.answer_max_tokens + 1500):
            return {"verdict": "revise", "feedback": "; ".join(problems), "revisions": revisions + 1}
        caveats = []
        if problems:
            text = repair(text, unsupported)
            # Caveats never repeat the offending IDs: that would put the fabricated ID back into the answer.
            if unsupported:
                caveats.append(f"{len(unsupported)} cited ID(s) could not be verified against the retrieved evidence and were removed.")
            if not any(e["items"] for e in evidence):
                caveats.append("No supporting evidence was retrieved, so the answer is reported as not found.")
                if parse_final(text).kind != "not_found":
                    text += "\nFINAL: NOT_FOUND"
            elif not unsupported:
                caveats.append("An automated claim check found statements the evidence does not support.")
        if run.exhausted:
            caveats.append(f"Partial evidence: the {', '.join(run.exhausted)} budget was reached.")
        supported = [i for i in extract_ids(text) if i in allowed]
        return {"verdict": "fail" if problems else "pass", "draft": text, "citations": supported, "caveats": caveats, "tokens": run.tokens}

    @staticmethod
    def _claim_check(run: Run, text: str, evidence: list[Any]) -> list[str]:
        block, _ = ev.render(evidence, run.config.evidence_chars)
        result = run.complete(
            [{"role": "system", "content": CLAIM_CHECK_SYSTEM}, {"role": "user", "content": f"Evidence:\n{block}\n\nAnswer:\n{text}"}],
            max_tokens=250, optional=True,
        )
        if result is None:
            return []
        try:
            return [str(c) for c in parse_json_object(result.text).get("unsupported", [])]
        except (ValueError, TypeError):
            return []


def plan_cost(run: Run) -> int:
    return run.config.cypher_max_tokens + 2000
