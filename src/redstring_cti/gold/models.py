"""Schema of the gold evaluation set (evals/gold/questions.jsonl)."""

import re
from pathlib import Path
from typing import Literal, Self

from pydantic import BaseModel, Field, model_validator

QuestionType = Literal["single_hop", "multi_hop", "aggregation", "semantic", "unanswerable"]
AnswerStyle = Literal["list", "ranked_list", "count", "not_found"]

# Same shapes the scorer extracts from answers, plus campaigns (C0024).
ID_PATTERN = re.compile(
    r"^(T\d{4}(\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|TA\d{4}|C\d{4}|CAPEC-\d+|CWE-\d+|CVE-\d{4}-\d+)$"
)
GOLD_PATH = Path(__file__).resolve().parents[3] / "evals" / "gold" / "questions.jsonl"
BUILD_INFO_PATH = GOLD_PATH.with_name("build_info.json")
MAX_GOLD_IDS = 60


class GoldQuestion(BaseModel):
    id: str = Field(pattern=r"^q\d{3}$")
    question: str = Field(min_length=15)
    type: QuestionType
    hops: int = Field(ge=0, le=4)
    answer_style: AnswerStyle
    gold_ids: list[str]
    gold_values: list[str]  # count answers, as strings
    gold_cypher: str
    precondition_cypher: str | None = None  # unanswerable: must return rows (the entity exists)
    split: Literal["dev", "test"]
    tags: list[str] = Field(default_factory=list)
    notes: str = ""

    @model_validator(mode="after")
    def _consistent(self) -> Self:
        if len(set(self.gold_ids)) != len(self.gold_ids):
            raise ValueError(f"{self.id}: duplicate gold ids")
        bad = [g for g in self.gold_ids if not ID_PATTERN.match(g)]
        if bad:
            raise ValueError(f"{self.id}: malformed gold ids {bad}")
        style = self.answer_style
        if style in ("list", "ranked_list") and not 1 <= len(self.gold_ids) <= MAX_GOLD_IDS:
            raise ValueError(f"{self.id}: {style} needs 1..{MAX_GOLD_IDS} gold ids, got {len(self.gold_ids)}")
        if style == "count" and (self.gold_ids or len(self.gold_values) != 1):
            raise ValueError(f"{self.id}: count needs exactly one gold value and no ids")
        if style == "not_found" and (self.gold_ids or self.gold_values):
            raise ValueError(f"{self.id}: not_found must have empty gold")
        if (self.type == "unanswerable") != (style == "not_found"):
            raise ValueError(f"{self.id}: unanswerable and not_found must go together")
        if self.type == "unanswerable" and self.hops != 0:
            raise ValueError(f"{self.id}: unanswerable questions have hops=0")
        if self.type != "unanswerable" and self.hops < 1:
            raise ValueError(f"{self.id}: answerable questions need hops >= 1")
        return self


def load_gold(path: Path = GOLD_PATH) -> list[GoldQuestion]:
    return [GoldQuestion.model_validate_json(line) for line in path.read_text().splitlines() if line.strip()]
