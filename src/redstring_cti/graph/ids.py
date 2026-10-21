"""Recognise ATT&CK / CAPEC / CWE / CVE identifiers and map them to graph labels and key properties."""

import re
from dataclasses import dataclass

# Order matters: TA#### must be tried before T####.
_KINDS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"TA\d{4}"), "Tactic", "attack_id"),
    (re.compile(r"T\d{4}(?:\.\d{3})?"), "Technique", "attack_id"),
    (re.compile(r"G\d{4}"), "Group", "attack_id"),
    (re.compile(r"S\d{4}"), "Software", "attack_id"),
    (re.compile(r"M\d{4}"), "Mitigation", "attack_id"),
    (re.compile(r"C\d{4}"), "Campaign", "attack_id"),
    (re.compile(r"CAPEC-\d+"), "CAPEC", "capec_id"),
    (re.compile(r"CWE-\d+"), "CWE", "cwe_id"),
    (re.compile(r"CVE-\d{4}-\d{4,}"), "CVE", "cve_id"),
]
LABELS = ("Group", "Technique", "Tactic", "Software", "Mitigation", "Campaign", "CAPEC", "CWE", "CVE")


def key_expr(var: str = "n") -> str:
    """Cypher expression for a node's identifier, whichever key property its label uses."""
    return f"coalesce({var}.attack_id, {var}.capec_id, {var}.cwe_id, {var}.cve_id)"



@dataclass(frozen=True)
class EntityRef:
    label: str
    key_prop: str
    key: str

    @property
    def uid(self) -> str:
        return f"{self.label}:{self.key}"


def parse_id(text: str) -> EntityRef | None:
    """'t1566.001' -> EntityRef(Technique, attack_id, 'T1566.001'); None when it is not an identifier."""
    candidate = text.strip().upper()
    for pattern, label, key_prop in _KINDS:
        if pattern.fullmatch(candidate):
            return EntityRef(label, key_prop, candidate)
    return None
