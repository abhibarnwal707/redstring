"""Deterministic answer scoring for the gold set (ID-based first, LLM judges later).

Systems end their answer with one line `FINAL: ...`:
  lists   -> IDs separated by commas (ranked order when a ranking was asked for)
  counts  -> just the number
  nothing -> `FINAL: NOT_FOUND`
The full answer text is still scanned for cited IDs (faithfulness checks).
"""

import re
from dataclasses import dataclass, field
from typing import Any

from redstring_cti.gold.models import GoldQuestion

ID_REGEX = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|G\d{4}|S\d{4}|M\d{4}|TA\d{4}|C\d{4}|CAPEC-\d+|CWE-\d+|CVE-\d{4}-\d+)\b")
# "FINAL:" normally starts a line, but models also write it inline after a sentence (sometimes after a
# narrow no-break space), so accept it after any whitespace; the last occurrence wins.
_FINAL_LINE = re.compile(r"(?:^|[\s\u202f\u00a0*])FINAL\**\s*:\s*(.*)$", re.IGNORECASE | re.MULTILINE)
_NUMBER = re.compile(r"-?\d[\d,]*(?:\.\d+)?")
_NOT_FOUND_TEXT = re.compile(r"\bnot found\b|\bno (?:such|matching) (?:entity|information|data|result)", re.IGNORECASE)
CORRECT_F1 = 0.8


def extract_ids(text: str) -> list[str]:
    """IDs in order of first appearance, de-duplicated."""
    return list(dict.fromkeys(ID_REGEX.findall(text)))


@dataclass
class Final:
    kind: str  # "ids" | "number" | "not_found" | "none" (no FINAL line)
    ids: list[str] = field(default_factory=list)
    number: str | None = None


def parse_final(text: str) -> Final:
    matches = _FINAL_LINE.findall(text)
    if not matches:
        return Final("none")
    content = matches[-1].strip().strip("*").strip()
    if content.upper().replace(" ", "_").startswith("NOT_FOUND"):
        return Final("not_found")
    ids = extract_ids(content)
    if ids:
        return Final("ids", ids=ids)
    m = _NUMBER.search(content)
    if m:
        return Final("number", number=normalise_number(m.group(0)))
    return Final("none")


def normalise_number(raw: str) -> str:
    cleaned = raw.replace(",", "")
    try:
        value = float(cleaned)
    except ValueError:
        return cleaned
    return str(int(value)) if value == int(value) else str(value)


def prf(predicted: list[str], gold: list[str]) -> tuple[float, float, float]:
    hits = len(set(predicted) & set(gold))
    precision = hits / len(set(predicted)) if predicted else 0.0
    recall = hits / len(set(gold)) if gold else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def score_question(q: GoldQuestion, text: str, evidence_ids: set[str] | None = None) -> dict[str, Any]:
    """Score one answer. `evidence_ids` are the IDs the system actually retrieved (for faithfulness)."""
    cited = extract_ids(text)
    final = parse_final(text)
    out: dict[str, Any] = {
        "predicted": [], "precision": 0.0, "recall": 0.0, "f1": 0.0, "correct": False,
        "order_exact": None, "said_not_found": final.kind == "not_found", "final_kind": final.kind,
    }
    if q.answer_style == "not_found":
        phrased = final.kind == "none" and bool(_NOT_FOUND_TEXT.search(text))
        out["correct"] = out["said_not_found"] or phrased
    elif q.answer_style == "count":
        if final.kind == "number":
            predicted = final.number
        else:  # no usable FINAL line: fall back to the last number in the text
            numbers = _NUMBER.findall(text)
            predicted = normalise_number(numbers[-1]) if numbers else None
        out["predicted"] = [predicted] if predicted else []
        out["correct"] = predicted == normalise_number(q.gold_values[0])
        out["f1"] = 1.0 if out["correct"] else 0.0
    else:
        predicted_ids = final.ids if final.kind == "ids" else (cited if final.kind == "none" else [])
        p, r, f1 = prf(predicted_ids, q.gold_ids)
        out.update(predicted=predicted_ids, precision=p, recall=r, f1=f1, correct=f1 >= CORRECT_F1)
        if q.answer_style == "ranked_list":
            out["order_exact"] = predicted_ids[: len(q.gold_ids)] == q.gold_ids
    allowed = set(evidence_ids or ()) | set(extract_ids(q.question))
    unsupported = [i for i in cited if i not in allowed] if evidence_ids is not None else []
    out["cited"] = cited
    out["unsupported_ids"] = unsupported
    return out
