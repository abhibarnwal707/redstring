"""Pieces shared by every question-answering system (baselines now, the agent later)."""

from dataclasses import dataclass, field
from typing import Any

from redstring_cti.llm import LLMResult
from redstring_cti.scoring import extract_ids

FINAL_RULES = """\
End your reply with exactly one line starting with "FINAL:".
- For a list, give only the IDs separated by commas (in ranked order if a ranking was requested).
- For "how" or "what kind of" questions, give the IDs of the entities that answer the question.
- For a count, give only the number.
- Write "FINAL: NOT_FOUND" only when the data you were given contains nothing that answers the question.
  If your reply states an answer, FINAL must contain it, never NOT_FOUND.
Cite IDs (such as T1566, G0016, CWE-89, CVE-2024-1234) inline for every fact you state."""


@dataclass
class SystemAnswer:
    """What a system produced for one question, with everything needed to score and audit it."""

    text: str
    evidence_ids: list[str] = field(default_factory=list)  # IDs the system actually retrieved
    calls: list[LLMResult] = field(default_factory=list)
    wall_s: float = 0.0
    cypher: str | None = None
    rows: int | None = None
    error: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def prompt_tokens(self) -> int:
        return sum(c.prompt_tokens for c in self.calls)

    @property
    def completion_tokens(self) -> int:
        return sum(c.completion_tokens for c in self.calls)

    @property
    def cost_usd(self) -> float:
        return sum(c.cost_usd for c in self.calls)

    @property
    def models(self) -> list[str]:
        return sorted({c.model for c in self.calls})

    @property
    def llm_latency_s(self) -> float:
        return sum(c.latency_s for c in self.calls)

    @property
    def waited_s(self) -> float:
        return sum(c.waited_s for c in self.calls)

    @property
    def service_s(self) -> float:
        """Wall time minus rate-limit waits: what the system costs with a quota that does not throttle."""
        return max(self.wall_s - self.waited_s, 0.0)


def ids_in(*chunks: str) -> list[str]:
    seen: dict[str, None] = {}
    for chunk in chunks:
        for i in extract_ids(chunk):
            seen[i] = None
    return list(seen)
