"""Scoring for extractor outputs (Phase 9 validation, reused by the Phase 10 comparison).

A prediction is VALID when it parses and validates against the Pydantic schema. Entities are compared as
(text, type) pairs: exact, and relaxed (case-insensitive text). Techniques are compared as id sets and
relations as (head, relation, tail) triples. An invalid prediction scores as an empty one, so invalid
output costs recall instead of vanishing from the denominator."""

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from redstring_cti.extractor.schema import Entity, Extraction, Relation, Technique


@dataclass
class Tally:
    tp: int = 0
    pred: int = 0
    gold: int = 0

    def add(self, predicted: set[object], gold: set[object]) -> None:
        self.tp += len(predicted & gold)
        self.pred += len(predicted)
        self.gold += len(gold)

    @property
    def precision(self) -> float:
        return self.tp / self.pred if self.pred else 0.0

    @property
    def recall(self) -> float:
        return self.tp / self.gold if self.gold else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if p + r else 0.0

    def row(self) -> dict[str, float | int]:
        return {"precision": round(self.precision, 3), "recall": round(self.recall, 3), "f1": round(self.f1, 3), "gold": self.gold}


@dataclass
class Scores:
    n: int = 0
    valid: int = 0
    entity_exact: Tally = field(default_factory=Tally)
    entity_relaxed: Tally = field(default_factory=Tally)
    technique: Tally = field(default_factory=Tally)
    relation: Tally = field(default_factory=Tally)
    technique_hits: Counter[str] = field(default_factory=Counter)  # per-id tp / pred / gold, for macro F1
    technique_pred: Counter[str] = field(default_factory=Counter)
    technique_gold: Counter[str] = field(default_factory=Counter)
    hallucinated_ids: int = 0
    predicted_ids: int = 0

    def summary(self) -> dict[str, Any]:
        ids = set(self.technique_gold) | set(self.technique_pred)
        f1s = []
        for i in ids:
            p = self.technique_hits[i] / self.technique_pred[i] if self.technique_pred[i] else 0.0
            r = self.technique_hits[i] / self.technique_gold[i] if self.technique_gold[i] else 0.0
            f1s.append(2 * p * r / (p + r) if p + r else 0.0)
        return {
            "n": self.n,
            "json_valid": round(self.valid / self.n, 3) if self.n else 0.0,
            "entity_exact": self.entity_exact.row(),
            "entity_relaxed": self.entity_relaxed.row(),
            "technique_micro": self.technique.row(),
            "technique_macro_f1": round(sum(f1s) / len(f1s), 3) if f1s else 0.0,
            "relation": self.relation.row(),
            "id_hallucination": round(self.hallucinated_ids / self.predicted_ids, 3) if self.predicted_ids else 0.0,
        }


def parse(raw: str) -> Extraction | None:
    try:
        return Extraction.from_json(raw.strip())
    except (ValidationError, ValueError):
        return None


def salvage(raw: str) -> Extraction | None:
    """For ingestion, not scoring: keep the parts of an almost-valid output that do validate (a bad entity type or a
    self-referencing relation should not discard a whole chunk). Truncated JSON cannot be salvaged."""
    try:
        data = json.loads(raw.strip())
        entities_raw, techniques_raw = data["entities"], data["techniques"]
    except (ValueError, KeyError, TypeError):
        return None
    entities: list[Entity] = []
    for item in entities_raw if isinstance(entities_raw, list) else []:
        try:
            entities.append(Entity.model_validate(item))
        except ValidationError:
            continue
    techniques: list[Technique] = []
    for item in techniques_raw if isinstance(techniques_raw, list) else []:
        try:
            techniques.append(Technique.model_validate(item))
        except ValidationError:
            continue
    names = {e.text for e in entities} | {t.attack_id for t in techniques}
    relations: list[Relation] = []
    for item in data.get("relations") or []:
        try:
            rel = Relation.model_validate(item)
        except ValidationError:
            continue
        if rel.head in names and rel.tail in names and rel.head != rel.tail and not (rel.head in {t.attack_id for t in techniques}):
            relations.append(rel)
    try:
        return Extraction(entities=entities, techniques=techniques, relations=relations if "relations" in data else None)
    except (ValidationError, ValueError):
        return None


def _sets(e: Extraction) -> tuple[set[tuple[str, str]], set[tuple[str, str]], set[str], set[tuple[str, str, str]]]:
    return (
        {(x.text, x.type) for x in e.entities},
        {(x.text.lower(), x.type) for x in e.entities},
        {t.attack_id for t in e.techniques},
        {(r.head, r.relation, r.tail) for r in (e.relations or [])},
    )


def score(pairs: list[tuple[str, str]], live_ids: set[str]) -> Scores:
    """`pairs` = (model output, gold JSON). Relations are only scored where the gold has a relations list."""
    s = Scores()
    empty = Extraction(entities=[], techniques=[])
    for raw, gold_json in pairs:
        gold = Extraction.from_json(gold_json)
        pred = parse(raw)
        s.n += 1
        s.valid += pred is not None
        pe, pl, pt, pr = _sets(pred or empty)
        ge, gl, gt, gr = _sets(gold)
        s.entity_exact.add(pe, ge)  # type: ignore[arg-type]
        s.entity_relaxed.add(pl, gl)  # type: ignore[arg-type]
        s.technique.add(pt, gt)  # type: ignore[arg-type]
        for i in pt:
            s.technique_pred[i] += 1
            s.technique_hits[i] += i in gt
            s.predicted_ids += 1
            s.hallucinated_ids += i not in live_ids
        for i in gt:
            s.technique_gold[i] += 1
        if gold.relations is not None:
            s.relation.add(pr, gr)  # type: ignore[arg-type]
    return s
