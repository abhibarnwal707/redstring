"""One training/evaluation example, before it is rendered as a chat message."""

from dataclasses import dataclass, field
from typing import Any

from redstring_cti.extractor.schema import Extraction


@dataclass
class Example:
    doc_id: str  # the unit that must never straddle two splits
    text: str
    extraction: Extraction
    source: str  # "attack_procedures" | "annoctr"
    split: str = ""  # train | val | test, assigned by the builder
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.source}:{self.doc_id}"
