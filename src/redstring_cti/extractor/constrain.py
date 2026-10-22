"""JSON schemas for constrained decoding: the model can only emit valid extractor output.

The schema fixes the shape, restricts entity and relation types to the allowed values, restricts technique ids to the
LIVE ATT&CK ids (so an invented id is impossible), and bounds list lengths (so a runaway repetition cannot occur).
Entity text stays free: it must be copied from the input, which a schema cannot express."""

from typing import Any

from redstring_cti.extractor.schema import TASK_FULL

ENTITY_TYPES = ["THREAT_ACTOR", "MALWARE", "TOOL", "CVE", "CAMPAIGN", "INFRASTRUCTURE"]
RELATION_TYPES = ["USES", "EXPLOITS", "ATTRIBUTED_TO", "TARGETS"]
MAX_ENTITIES, MAX_TECHNIQUES, MAX_RELATIONS = 30, 25, 20


def extraction_schema(task: str, live_ids: set[str]) -> dict[str, Any]:
    ids = sorted(live_ids)
    properties: dict[str, Any] = {
        "entities": {"type": "array", "maxItems": MAX_ENTITIES, "items": {"type": "object", "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 80}, "type": {"enum": ENTITY_TYPES}}, "required": ["text", "type"]}},
        "techniques": {"type": "array", "maxItems": MAX_TECHNIQUES, "items": {"type": "object", "properties": {"attack_id": {"enum": ids}}, "required": ["attack_id"]}},
    }
    required = ["entities", "techniques"]
    if task == TASK_FULL:
        properties["relations"] = {
            "type": "array", "maxItems": MAX_RELATIONS,
            "items": {"type": "object", "properties": {"head": {"type": "string", "minLength": 1, "maxLength": 80}, "relation": {"enum": RELATION_TYPES}, "tail": {"type": "string", "minLength": 1, "maxLength": 80}}, "required": ["head", "relation", "tail"]},
        }
        required.append("relations")
    return {"type": "object", "properties": properties, "required": required}
