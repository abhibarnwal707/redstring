"""Helpers shared by all ingesters."""

import re
from collections.abc import Iterable, Iterator
from itertools import islice

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
