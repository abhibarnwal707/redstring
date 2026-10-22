"""Agent state, plan schema, budgets and the per-run ledger."""

import operator
import time
from dataclasses import dataclass, field
from typing import Annotated, Any, Literal, TypedDict

from pydantic import BaseModel, Field, field_validator

from redstring_cti.agent.toolbox import Toolbox, ToolCallError
from redstring_cti.graph.ids import LABELS
from redstring_cti.llm import LLMClient, LLMResult

Route = Literal["graph", "vector", "hybrid", "cve_live", "unanswerable", "reports"]
Pattern = Literal["lookup", "neighbors", "paths", "cypher", "search"]
Verdict = Literal["pass", "revise", "fail"]


class Mention(BaseModel):
    text: str
    label: str | None = None

    @field_validator("label")
    @classmethod
    def _known_label(cls, v: str | None) -> str | None:
        return v if v in LABELS else None


class Plan(BaseModel):
    route: Route
    pattern: Pattern | None = None
    mentions: list[Mention] = Field(default_factory=list)
    target_label: str | None = None
    kev_only: bool = False

    @field_validator("target_label")
    @classmethod
    def _known_target(cls, v: str | None) -> str | None:
        return v if v in LABELS else None

    @field_validator("pattern", mode="before")
    @classmethod
    def _blank_pattern(cls, v: Any) -> Any:
        return None if v in ("", "none", "null") else v


class Evidence(TypedDict):
    tool: str
    args: dict[str, Any]
    text: str  # what the answering model sees
    ids: list[str]  # IDs that appear in `text` (the only ones the answer may cite)
    triples: list[list[str]]  # [source, relationship, target], for citing paths
    items: int


class AgentState(TypedDict, total=False):
    question: str
    plan: dict[str, Any]
    route: Route
    pattern: Pattern | None
    entities: list[dict[str, Any]]  # resolved: id, label, name, ambiguous
    unresolved: list[str]
    evidence: Annotated[list[Evidence], operator.add]
    draft: str | None
    citations: list[str]
    tool_calls: int
    tokens: int
    verdict: Verdict | None
    revisions: int
    feedback: str | None
    caveats: Annotated[list[str], operator.add]
    run: "Run"


@dataclass
class AgentConfig:
    max_tool_calls: int = 8
    max_tokens: int = 14_000  # prompt + completion over the whole question
    timeout_s: float = 300.0  # wall clock, includes free-tier rate-limit waits
    max_revisions: int = 1
    llm_check: bool = False  # extra LLM claim check in self_check (ablation: faithfulness vs latency/tokens)
    use_templates: bool = True  # ablation: False = free-form Cypher for every graph question (no neighbors / find_paths templates)
    self_check: bool = True  # ablation: False = accept the first answer, no citation check, no revision
    reasoning_effort: str = "low"
    plan_max_tokens: int = 400
    answer_max_tokens: int = 500
    cypher_max_tokens: int = 450
    evidence_chars: int = 7000  # about 2,000 tokens of evidence in the answering prompt


class BudgetExceeded(RuntimeError):
    pass


@dataclass
class Run:
    """Everything one question consumed: model calls, tool calls, time. Budgets are enforced here."""

    config: AgentConfig
    toolbox: Toolbox
    llm: LLMClient
    started: float = field(default_factory=time.monotonic)
    llm_calls: list[LLMResult] = field(default_factory=list)
    tool_log: list[dict[str, Any]] = field(default_factory=list)
    exhausted: list[str] = field(default_factory=list)  # which budgets ran out

    @property
    def tokens(self) -> int:
        return sum(c.prompt_tokens + c.completion_tokens for c in self.llm_calls)

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def time_left(self) -> bool:
        return self.elapsed < self.config.timeout_s

    def can_spend(self, tokens: int) -> bool:
        return self.tokens + tokens <= self.config.max_tokens and self.time_left()

    def tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Call a tool, logging it. Raises BudgetExceeded when the tool-call or time budget is gone,
        and ToolCallError (after logging) when the tool reports an error."""
        if len(self.tool_log) >= self.config.max_tool_calls:
            self._note("tool_calls")
            raise BudgetExceeded("tool-call budget used up")
        if not self.time_left():
            self._note("time")
            raise BudgetExceeded("time budget used up")
        started = time.perf_counter()
        entry: dict[str, Any] = {"tool": name, "args": args}
        try:
            result = self.toolbox.call(name, args)
        except ToolCallError as exc:
            entry.update(ok=False, error=str(exc)[:200], ms=round((time.perf_counter() - started) * 1000, 1))
            self.tool_log.append(entry)
            raise
        for key in ("results", "neighbors", "paths", "rows", "candidates"):
            if isinstance(result.get(key), list):
                entry["rows"] = len(result[key])
                break
        entry.update(ok=True, ms=round((time.perf_counter() - started) * 1000, 1))
        self.tool_log.append(entry)
        return result

    def complete(self, messages: list[dict[str, str]], *, max_tokens: int, optional: bool = False) -> LLMResult | None:
        """One model call. Optional calls (retries, extra checks) are skipped when the token budget is tight."""
        if optional and not self.can_spend(max_tokens + sum(len(m["content"]) for m in messages) // 3):
            self._note("tokens")
            return None
        result = self.llm.complete(messages, max_tokens=max_tokens, reasoning_effort=self.config.reasoning_effort)
        self.llm_calls.append(result)
        if self.tokens > self.config.max_tokens:
            self._note("tokens")
        return result

    def _note(self, what: str) -> None:
        if what not in self.exhausted:
            self.exhausted.append(what)
