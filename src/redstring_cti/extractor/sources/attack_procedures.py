"""Training examples from ATT&CK procedure examples: the sentence on every `uses` relationship.

MITRE links every actor, software and technique it names (`[APT29](https://attack.mitre.org/groups/G0016)`),
so entity and technique labels come with the text for free and are accurate. The relationship itself
(source USES technique) gives a verified relation. Each example's `doc_id` is its source object, so all
sentences about one actor or tool land in the same split."""

import re
from collections import Counter
from pathlib import Path
from typing import Any

import orjson

from redstring_cti.extractor.attack_ids import AttackIds, technique_id_from_url
from redstring_cti.extractor.records import Example
from redstring_cti.extractor.schema import Entity, Extraction, Relation, Technique
from redstring_cti.ingest.common import strip_markup

SOURCE = "attack_procedures"
MIN_CHARS, MAX_CHARS = 40, 1000
_LINK = re.compile(r"\[([^\]]+)\]\((https?://attack\.mitre\.org/(groups|software|campaigns|techniques)/[^)\s]+)\)")
_SOURCE_TYPES = {"intrusion-set", "malware", "tool", "campaign"}


def _ext_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref["external_id"]) if ref.get("external_id") else None
    return None


def _live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _entity_type(kind: str, software_type: dict[str, str], attack_id: str) -> str | None:
    if kind == "groups":
        return "THREAT_ACTOR"
    if kind == "campaigns":
        return "CAMPAIGN"
    if kind == "software":
        return "TOOL" if software_type.get(attack_id) == "tool" else "MALWARE"
    return None


def load_examples(bundle: Path, ids: AttackIds) -> tuple[list[Example], Counter[str]]:
    """Returns the examples and a Counter explaining every dropped relationship."""
    objects: list[dict[str, Any]] = orjson.loads(bundle.read_bytes())["objects"]
    by_stix = {o["id"]: o for o in objects}
    software_type = {i: o["type"] for o in objects if o["type"] in ("malware", "tool") and (i := _ext_id(o))}
    drops: Counter[str] = Counter()
    examples: list[Example] = []
    for rel in objects:
        if rel["type"] != "relationship" or rel.get("relationship_type") != "uses":
            continue
        src, tgt = by_stix.get(rel["source_ref"]), by_stix.get(rel["target_ref"])
        if not src or not tgt or src["type"] not in _SOURCE_TYPES or tgt["type"] != "attack-pattern":
            continue
        if not (_live(src) and _live(tgt)) or not rel.get("description"):
            drops["not live or no description"] += 1
            continue
        tech_id, src_id = _ext_id(tgt), _ext_id(src)
        if not tech_id or not src_id or tech_id not in ids.live:
            drops["technique not live"] += 1
            continue
        raw = rel["description"]
        text = strip_markup(raw) or ""
        if not MIN_CHARS <= len(text) <= MAX_CHARS:
            drops["text length"] += 1
            continue

        entities: dict[str, str] = {}
        techniques = {tech_id}
        source_surface: str | None = None
        for surface, url, kind in _LINK.findall(raw):
            if kind == "techniques":
                linked = technique_id_from_url(url)
                if linked and (cur := ids.current(linked)):
                    techniques.add(cur)
                continue
            attack_id = url.rstrip("/").rsplit("/", 1)[-1]
            etype = _entity_type(kind, software_type, attack_id)
            if etype and surface in text:
                entities.setdefault(surface, etype)
                if attack_id == src_id and source_surface is None:
                    source_surface = surface
        if source_surface is None:  # the source is not linked: fall back to its own name or alias if it appears verbatim
            names = [src.get("name", ""), *src.get("aliases", []), *src.get("x_mitre_aliases", [])]
            source_surface = next((n for n in names if n and n in text), None)
            if source_surface is not None:
                etype = {"intrusion-set": "THREAT_ACTOR", "campaign": "CAMPAIGN"}.get(src["type"]) or ("TOOL" if src["type"] == "tool" else "MALWARE")
                entities.setdefault(source_surface, etype)
        if source_surface is None:
            drops["source not named in the sentence"] += 1
            continue
        extraction = Extraction(
            entities=[Entity(text=t, type=ty) for t, ty in entities.items()],  # type: ignore[arg-type]
            techniques=[Technique(attack_id=t) for t in sorted(techniques)],
            relations=[Relation(head=source_surface, relation="USES", tail=tech_id)],
        ).canonical()
        examples.append(Example(doc_id=src["id"], text=text, extraction=extraction, source=SOURCE,
                                meta={"technique": tech_id, "source_object": src_id}))
    return examples, drops
