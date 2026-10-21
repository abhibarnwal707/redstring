"""Helpers shared by all ingesters."""

import re
from collections.abc import Iterable, Iterator
from itertools import islice
from typing import Any

from pydantic import BaseModel, Field

# "(Citation: Name (with parens))" and "[text](https://...)" as found in ATT&CK descriptions
_CITATION = re.compile(r"\(Citation:[^()]*(?:\([^()]*\)[^()]*)*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\((?:https?://)[^)]*\)")


def strip_markup(text: str | None) -> str | None:
    """Remove ATT&CK citations and turn markdown links into their link text."""
    if text is None:
        return None
    cleaned = _MD_LINK.sub(r"\1", _CITATION.sub("", text))
    return re.sub(r"[ \t]{2,}", " ", cleaned).strip()


def batched[T](items: Iterable[T], size: int) -> Iterator[list[T]]:
    it = iter(items)
    while batch := list(islice(it, size)):
        yield batch


class Node(BaseModel):
    label: str
    key_prop: str  # e.g. attack_id, cwe_id, capec_id, cve_id
    key: str
    props: dict[str, Any]

    @property
    def uid(self) -> str:
        return f"{self.label}:{self.key}"


class Edge(BaseModel):
    rel: str
    src_label: str
    src_prop: str
    src_key: str
    dst_label: str
    dst_prop: str
    dst_key: str
    props: dict[str, Any] = Field(default_factory=dict)


def clean_text(text: str | None) -> str | None:
    """Collapse whitespace; None and empty strings become None."""
    if text is None:
        return None
    collapsed = " ".join(text.split())
    return collapsed or None
