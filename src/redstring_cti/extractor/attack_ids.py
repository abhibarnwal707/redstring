"""ATT&CK technique IDs over time: which are live in the pinned version, and where revoked ones went.

Older datasets (AnnoCTR links to ATT&CK from 2021) use IDs that have since been revoked or merged
(for example T1086 became T1059.001). `revoked-by` relationships in the STIX bundle record the successor."""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import orjson

_TECHNIQUE_URL = re.compile(r"attack\.mitre\.org/techniques/(T\d{4})(?:/(\d{3}))?", re.IGNORECASE)


def technique_id_from_url(url: str) -> str | None:
    """'https://attack.mitre.org/techniques/T1055/012' -> 'T1055.012'."""
    m = _TECHNIQUE_URL.search(url)
    if not m:
        return None
    return f"{m.group(1).upper()}.{m.group(2)}" if m.group(2) else m.group(1).upper()


def _external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref["external_id"]) if ref.get("external_id") else None
    return None


@dataclass
class AttackIds:
    live: set[str]
    successor: dict[str, str] = field(default_factory=dict)  # revoked or deprecated id -> replacement id
    names: dict[str, str] = field(default_factory=dict)

    def current(self, technique_id: str) -> str | None:
        """The live id for `technique_id`: itself, its (transitive) successor, or None when it is gone."""
        seen: set[str] = set()
        while technique_id not in seen:
            if technique_id in self.live:
                return technique_id
            seen.add(technique_id)
            nxt = self.successor.get(technique_id)
            if nxt is None:
                return None
            technique_id = nxt
        return None


def load_attack_ids(bundle: Path) -> AttackIds:
    objects: list[dict[str, Any]] = orjson.loads(bundle.read_bytes())["objects"]
    by_stix = {o["id"]: o for o in objects if o["type"] == "attack-pattern"}
    live: set[str] = set()
    names: dict[str, str] = {}
    for o in by_stix.values():
        ext = _external_id(o)
        if ext and not o.get("revoked") and not o.get("x_mitre_deprecated"):
            live.add(ext)
            names[ext] = o.get("name", "")
    successor: dict[str, str] = {}
    for o in objects:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            old, new = by_stix.get(o["source_ref"]), by_stix.get(o["target_ref"])
            if old and new and (old_id := _external_id(old)) and (new_id := _external_id(new)):
                successor[old_id] = new_id
    return AttackIds(live=live, successor=successor, names=names)
