"""AnnoCTR (CC BY-SA 4.0, Bosch Research): expert-annotated real cyber threat reports.

Conversion:
* entities  <- the sentence-level NER layer (`ce_tags`: GROUP, MALWARE, TOOL), plus CVE ids found by regex;
* techniques <- explicit and implicit technique spans (`ce_tags` / `ci_tags`), whose ATT&CK ids come from the
  document's linking layer through a phrase -> id dictionary, mapped to the pinned ATT&CK version;
* chunks    <- consecutive sentences up to ~MAX_CHUNK_CHARS. A chunk with a technique mention that cannot be
  resolved to a current id is DROPPED: an incomplete label is worse than a missing example.
No relation labels exist in AnnoCTR, so these examples use the entities+techniques task.
The official train/dev/test document split is kept (dev becomes validation)."""

import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson

from redstring_cti.extractor.attack_ids import AttackIds, technique_id_from_url
from redstring_cti.extractor.records import Example
from redstring_cti.extractor.schema import Entity, Extraction, Technique

SOURCE = "annoctr"
MAX_CHUNK_CHARS = 1500
SPLIT_NAMES = {"train": "train", "dev": "val", "test": "test"}
ENTITY_TYPES = {"GROUP": "THREAT_ACTOR", "MALWARE": "MALWARE", "TOOL": "TOOL"}
_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")
_LINK_KIND = re.compile(r"attack\.mitre\.org/(\w+)/")
_URL_SLUG = re.compile(r"^[a-z0-9]+(-[a-z0-9]+){3,}$")
_NORM = re.compile(r"[^a-z0-9]+")


def norm_phrase(text: str) -> str:
    """Case- and punctuation-insensitive key for matching a span to a linking mention."""
    return _NORM.sub(" ", text.lower()).strip()


def bio_spans(tags: list[str]) -> list[tuple[int, int, str]]:
    """BIO tags -> (start, end_exclusive, type) spans."""
    spans: list[tuple[int, int, str]] = []
    start: int | None = None
    kind = ""
    for i, tag in enumerate([*tags, "O"]):
        if tag == "O" or tag.startswith("B-") or (tag.startswith("I-") and tag[2:] != kind):
            if start is not None:
                spans.append((start, i, kind))
                start = None
            if tag != "O":
                start, kind = i, tag[2:]
        elif tag.startswith("I-") and start is None:
            start, kind = i, tag[2:]
    return spans


def surface(sentence: str, tokens: list[str], start: int, end: int) -> str | None:
    """The exact substring of `sentence` covered by tokens[start:end], tolerant of tokenisation spacing."""
    pieces = tokens[start:end]
    if not pieces:
        return None
    m = re.search(r"\s*".join(re.escape(p) for p in pieces), sentence)
    return m.group(0).strip() if m else None


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    for line in path.read_text().splitlines():
        if line.strip():
            yield orjson.loads(line)


def technique_dictionary(linking_file: Path, ids: AttackIds) -> tuple[dict[str, dict[str, set[str]]], Counter[str]]:
    """document -> normalised mention -> current technique ids. Rows whose annotated type disagrees with
    the ATT&CK link kind (0.2 % of rows) are skipped."""
    out: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    stats: Counter[str] = Counter()
    for row in _jsonl(linking_file):
        kind = _LINK_KIND.search(row.get("label_link") or "")
        if row["entity_type"] != "TECHNIQUE" or not kind:
            continue
        if kind.group(1) != "techniques":
            stats["technique row linked to a non-technique (skipped)"] += 1
            continue
        raw = technique_id_from_url(row["label_link"])
        current = ids.current(raw) if raw else None
        stats["technique links"] += 1
        if current is None:
            stats["technique links without a current id"] += 1
            out[row["document"]][norm_phrase(row["mention"])].add("")  # remember that it exists but cannot be used
        else:
            stats["technique links mapped" if current != raw else "technique links unchanged"] += 1
            out[row["document"]][norm_phrase(row["mention"])].add(current)
    return out, stats


def load_split(root: Path, split: str, ids: AttackIds, stats: Counter[str]) -> list[Example]:
    base = root / "AnnoCTR"
    dictionary, link_stats = technique_dictionary(base / "linking_mitre_only" / f"{split}.jsonl", ids)
    stats.update({f"{split}: {k}": v for k, v in link_stats.items()})
    sentences: dict[str, list[tuple[int, dict[str, Any]]]] = defaultdict(list)
    for row in _ner_rows(base / "ner_json" / f"{split}.json"):
        doc, _, idx = row["id"].rpartition("__s")
        sentences[doc].append((int(idx), row))

    examples: list[Example] = []
    for doc, rows in sorted(sentences.items()):
        rows.sort(key=lambda x: x[0])
        examples += _chunk_document(doc, [r for _, r in rows], dictionary.get(doc, {}), stats, split)
    return examples


Annotated = tuple[str, list[Entity], set[str], bool]  # sentence text, entities, technique ids, unresolved technique mention


def _make_example(doc: str, chunk: list[Annotated], number: int, split: str, stats: Counter[str]) -> Example | None:
    """`number` is the chunk's position in its document, counting dropped chunks, so ids survive filter changes."""
    stats[f"{split}: chunks built"] += 1
    if any(c[3] for c in chunk):
        stats[f"{split}: chunks dropped (unresolvable technique mention)"] += 1
        return None
    entities = [e for c in chunk for e in c[1]]
    techniques = set().union(*(c[2] for c in chunk))
    extraction = Extraction(entities=entities, techniques=[Technique(attack_id=t) for t in techniques]).canonical()
    return Example(doc_id=doc, text="\n".join(c[0] for c in chunk), extraction=extraction, source=SOURCE,
                   split=SPLIT_NAMES[split], meta={"chunk": number})


def _chunk_document(doc: str, rows: list[dict[str, Any]], doc_techniques: dict[str, set[str]], stats: Counter[str], split: str) -> list[Example]:
    out: list[Example] = []
    chunk: list[Annotated] = []
    size = 0
    built = 0
    for row in rows:
        sentence = row["text"].strip()
        if not re.search(r"[A-Za-z]{3}", sentence):
            continue  # separators and empty headings
        ents, techs, tainted = _annotate(row, sentence, doc_techniques, stats, split)
        if chunk and size + len(sentence) > MAX_CHUNK_CHARS:
            if (ex := _make_example(doc, chunk, built, split, stats)) is not None:
                out.append(ex)
            built += 1
            chunk, size = [], 0
        chunk.append((sentence, ents, techs, tainted))
        size += len(sentence) + 1
    if chunk and (ex := _make_example(doc, chunk, built, split, stats)) is not None:
        out.append(ex)
    return out


def _ner_rows(path: Path) -> Iterator[dict[str, Any]]:
    """ner_json is one JSON object per line despite its extension."""
    for line in path.read_text().splitlines():
        if line.strip():
            yield orjson.loads(line)


def _annotate(row: dict[str, Any], sentence: str, doc_techniques: dict[str, set[str]], stats: Counter[str], split: str) -> tuple[list[Entity], set[str], bool]:
    tokens: list[str] = row["tokens"]
    entities: list[Entity] = []
    for start, end, kind in bio_spans(row["ce_tags"]):
        if kind in ENTITY_TYPES:
            text = (surface(sentence, tokens, start, end) or "").rstrip(".,;:")
            if _URL_SLUG.match(text):
                stats[f"{split}: entity spans dropped (URL slug)"] += 1
            elif text:
                entities.append(Entity(text=text, type=ENTITY_TYPES[kind]))  # type: ignore[arg-type]
            else:
                stats[f"{split}: entity spans not found in the sentence text"] += 1
    for m in _CVE.finditer(sentence):
        entities.append(Entity(text=m.group(0), type="CVE"))
    technique_ids: set[str] = set()
    tainted = False
    # Strict labels (hand review of 80 test chunks found unsupported techniques): only EXPLICIT technique
    # mentions whose phrase maps to exactly one current id count. A chunk holding an implicit mention (inferred
    # by the annotator, not stated) or an ambiguous phrase is dropped rather than given an incomplete label.
    if any(k == "TECHNIQUE" for _, _, k in bio_spans(row["ci_tags"])):
        tainted = True
        stats[f"{split}: chunks tainted by an implicit technique mention"] += 1
    for start, end, kind in bio_spans(row["ce_tags"]):
        if kind != "TECHNIQUE":
            continue
        phrase = surface(sentence, tokens, start, end) or " ".join(tokens[start:end])
        found = doc_techniques.get(norm_phrase(phrase), set())
        if len(found) == 1 and "" not in found:
            technique_ids |= found
            stats[f"{split}: technique spans resolved"] += 1
        else:
            tainted = True
            stats[f"{split}: technique spans unresolved or ambiguous"] += 1
    return entities, technique_ids, tainted


def load_all(root: Path, ids: AttackIds) -> tuple[list[Example], Counter[str]]:
    stats: Counter[str] = Counter()
    examples: list[Example] = []
    for split in SPLIT_NAMES:
        examples += load_split(root, split, ids, stats)
    return examples, stats
