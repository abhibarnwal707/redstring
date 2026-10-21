"""The extractor's target: what a threat-report chunk is turned into.

Deliberately small (a small schema learned well beats a big one learned badly):
* entities carry text and type only. Mapping a name to its ATT&CK/graph id is a lookup done by the entity
  linker against the graph, not something a 1.7B model should memorise;
* techniques carry the ATT&CK id (a real classification task);
* relations are optional: only some training sources have trustworthy relation labels, so the task prompt says
  whether relations are requested.
Serialised as minified JSON with a fixed key order so the model learns one exact shape."""

import re
from typing import Literal

import orjson
from pydantic import BaseModel, field_validator, model_validator

EntityType = Literal["THREAT_ACTOR", "MALWARE", "TOOL", "CVE", "CAMPAIGN", "INFRASTRUCTURE"]
RelationType = Literal["USES", "EXPLOITS", "ATTRIBUTED_TO", "TARGETS"]
TASK_ENTITIES_TECHNIQUES = "entities_techniques"
TASK_FULL = "full"
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")

SYSTEM_PROMPTS = {
    TASK_FULL: (
        "Extract the cyber-threat entities, MITRE ATT&CK technique ids and relations from the text. "
        'Reply with minified JSON only: {"entities":[{"text","type"}],"techniques":[{"attack_id"}],"relations":[{"head","relation","tail"}]}. '
        "Entity types: THREAT_ACTOR, MALWARE, TOOL, CVE, CAMPAIGN, INFRASTRUCTURE. Relations: USES, EXPLOITS, ATTRIBUTED_TO, TARGETS. "
        "Entity text must be copied exactly from the input. Use empty lists when nothing applies."
    ),
    TASK_ENTITIES_TECHNIQUES: (
        "Extract the cyber-threat entities and MITRE ATT&CK technique ids from the text. "
        'Reply with minified JSON only: {"entities":[{"text","type"}],"techniques":[{"attack_id"}]}. '
        "Entity types: THREAT_ACTOR, MALWARE, TOOL, CVE, CAMPAIGN, INFRASTRUCTURE. "
        "Entity text must be copied exactly from the input. Use empty lists when nothing applies."
    ),
}


class Entity(BaseModel):
    text: str
    type: EntityType

    @field_validator("text")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        if not v.strip() or v != v.strip():
            raise ValueError("entity text must be non-empty and trimmed")
        return v


class Technique(BaseModel):
    attack_id: str

    @field_validator("attack_id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not _TECHNIQUE.match(v):
            raise ValueError(f"not an ATT&CK technique id: {v!r}")
        return v


class Relation(BaseModel):
    head: str
    relation: RelationType
    tail: str


class Extraction(BaseModel):
    entities: list[Entity]
    techniques: list[Technique]
    relations: list[Relation] | None = None  # None: not requested for this task

    @model_validator(mode="after")
    def _relations_refer_to_the_extraction(self) -> "Extraction":
        if self.relations is None:
            return self
        names = {e.text for e in self.entities}
        ids = {t.attack_id for t in self.techniques}
        for r in self.relations:
            if r.head not in names:
                raise ValueError(f"relation head {r.head!r} is not an extracted entity")
            if r.tail not in names and r.tail not in ids and not _CVE.match(r.tail):
                raise ValueError(f"relation tail {r.tail!r} is neither an entity, a technique id nor a CVE")
        return self

    @property
    def task(self) -> str:
        return TASK_ENTITIES_TECHNIQUES if self.relations is None else TASK_FULL

    def canonical(self) -> "Extraction":
        """Deduplicated and sorted, so equal extractions serialise identically."""
        entities = sorted({(e.text, e.type) for e in self.entities}, key=lambda x: (x[0].lower(), x[0], x[1]))  # a total order: "REvil" and "Revil" must not tie
        techniques = sorted({t.attack_id for t in self.techniques})
        out = Extraction(entities=[Entity(text=t, type=ty) for t, ty in entities], techniques=[Technique(attack_id=i) for i in techniques])
        if self.relations is not None:
            rel = sorted({(r.head, r.relation, r.tail) for r in self.relations})
            out.relations = [Relation(head=h, relation=r, tail=t) for h, r, t in rel]
        return out

    def to_json(self) -> str:
        """Minified, fixed key order (entities, techniques, relations)."""
        data = self.canonical().model_dump(exclude_none=True)
        return orjson.dumps(data).decode()

    @classmethod
    def from_json(cls, text: str) -> "Extraction":
        return cls.model_validate(orjson.loads(text))
