"""The LangGraph agent: plan -> resolve entities -> retrieve (graph / vector / hybrid / live CVE / ingested reports) -> answer -> self-check."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langgraph.graph import END, START, StateGraph

from redstring_cti.agent.nodes import AgentNodes
from redstring_cti.agent.state import AgentConfig, AgentState, Run
from redstring_cti.agent.toolbox import Toolbox
from redstring_cti.gold.models import GOLD_PATH, load_gold
from redstring_cti.llm import LLMClient
from redstring_cti.retrieval import text2cypher
from redstring_cti.retrieval.common import SystemAnswer
from redstring_cti.scoring import extract_ids


@dataclass
class AgentResult:
    answer: str
    citations: list[str]
    paths: list[list[str]]
    route: str
    pattern: str | None
    verdict: str
    caveats: list[str]
    entities: list[dict[str, Any]]
    tool_calls: int
    llm_calls: int
    tokens: int
    cost_usd: float
    latency_ms: float  # service time: wall clock minus rate-limit waits
    wall_ms: float
    budget_exhausted: list[str]
    models: list[str]
    tool_log: list[dict[str, Any]] = field(default_factory=list)


def build_graph(nodes: AgentNodes) -> Any:
    g: StateGraph = StateGraph(AgentState)
    g.add_node("plan_route", nodes.plan_route)
    g.add_node("resolve_entities", nodes.resolve_entities)
    g.add_node("graph_retrieve", nodes.graph_retrieve)
    g.add_node("vector_retrieve", nodes.vector_retrieve)
    g.add_node("cve_node", nodes.cve_node)
    g.add_node("report_node", nodes.report_node)
    g.add_node("answer", nodes.answer)
    g.add_node("self_check", nodes.self_check)
    g.add_edge(START, "plan_route")
    g.add_edge("plan_route", "resolve_entities")

    def after_resolve(state: AgentState) -> str:
        return {"graph": "graph_retrieve", "hybrid": "graph_retrieve", "vector": "vector_retrieve", "cve_live": "cve_node", "reports": "report_node"}.get(state["route"], "answer")

    g.add_conditional_edges("resolve_entities", after_resolve, ["graph_retrieve", "vector_retrieve", "cve_node", "report_node", "answer"])
    g.add_conditional_edges("graph_retrieve", lambda s: "vector_retrieve" if s["route"] == "hybrid" else "answer", ["vector_retrieve", "answer"])
    g.add_edge("vector_retrieve", "answer")
    g.add_edge("cve_node", "answer")
    g.add_edge("report_node", "answer")
    g.add_edge("answer", "self_check")
    g.add_conditional_edges("self_check", lambda s: "answer" if s["verdict"] == "revise" else END, ["answer", END])
    return g.compile()


class Agent:
    def __init__(self, llm: LLMClient, toolbox: Toolbox, config: AgentConfig | None = None, fewshot: str | None = None, gold_path: Path = GOLD_PATH) -> None:
        self.llm, self.toolbox, self.config = llm, toolbox, config or AgentConfig()
        self._nodes = AgentNodes(fewshot if fewshot is not None else text2cypher.build_fewshot(load_gold(gold_path)))
        self._graph = build_graph(self._nodes)

    def run(self, question: str) -> AgentResult:
        run = Run(config=self.config, toolbox=self.toolbox, llm=self.llm)
        state = self._graph.invoke({"question": question, "run": run, "evidence": [], "caveats": [], "revisions": 0})
        waited = sum(c.waited_s for c in run.llm_calls)
        wall = run.elapsed
        text = state["draft"] or ""
        if state.get("caveats"):
            text += "\n\nNote: " + " ".join(state["caveats"])
        return AgentResult(
            answer=text, citations=state.get("citations", []),
            paths=[t for e in state.get("evidence", []) for t in e["triples"]],
            route=state["route"], pattern=state.get("pattern"), verdict=state.get("verdict") or "pass",
            caveats=state.get("caveats", []), entities=state.get("entities", []),
            tool_calls=len(run.tool_log), llm_calls=len(run.llm_calls), tokens=run.tokens,
            cost_usd=sum(c.cost_usd for c in run.llm_calls), latency_ms=max(wall - waited, 0.0) * 1000, wall_ms=wall * 1000,
            budget_exhausted=run.exhausted, models=sorted({c.model for c in run.llm_calls}), tool_log=run.tool_log,
        )

    def answer(self, question: str) -> SystemAnswer:
        """The same run, shaped for the evaluation harness (scoring needs the FINAL line without the appended note)."""
        run = Run(config=self.config, toolbox=self.toolbox, llm=self.llm)
        state = self._graph.invoke({"question": question, "run": run, "evidence": [], "caveats": [], "revisions": 0})
        evidence_ids = sorted({i for e in state.get("evidence", []) for i in e["ids"]} | set(extract_ids(question)))
        return SystemAnswer(
            text=state["draft"] or "", evidence_ids=evidence_ids, calls=list(run.llm_calls), wall_s=run.elapsed,
            cypher=next((e["args"].get("cypher") for e in state.get("evidence", []) if e["tool"] == "cypher_query"), None),
            rows=sum(e["items"] for e in state.get("evidence", [])),
            extra={"route": state["route"], "pattern": state.get("pattern"), "verdict": state.get("verdict"), "tool_calls": len(run.tool_log),
                   "tools": [t["tool"] for t in run.tool_log], "budget_exhausted": run.exhausted, "caveats": state.get("caveats", []),
                   "entities": [e["id"] for e in state.get("entities", [])]},
        )

    def close(self) -> None:
        self.toolbox.close()
