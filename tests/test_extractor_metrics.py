from redstring_cti.extractor import metrics
from redstring_cti.extractor.schema import Entity, Extraction, Relation, Technique

LIVE = {"T1486", "T1059", "T1566"}


def js(entities: list[tuple[str, str]], techniques: list[str], relations: list[tuple[str, str, str]] | None = None) -> str:
    return Extraction(
        entities=[Entity(text=t, type=ty) for t, ty in entities],  # type: ignore[arg-type]
        techniques=[Technique(attack_id=i) for i in techniques],
        relations=None if relations is None else [Relation(head=h, relation=r, tail=t) for h, r, t in relations],  # type: ignore[arg-type]
    ).to_json()


def test_perfect_prediction_scores_one() -> None:
    gold = js([("APT29", "THREAT_ACTOR")], ["T1566"], [("APT29", "USES", "T1566")])
    s = metrics.score([(gold, gold)], LIVE).summary()
    assert s["json_valid"] == 1.0 and s["entity_exact"]["f1"] == 1.0 and s["technique_micro"]["f1"] == 1.0 and s["relation"]["f1"] == 1.0
    assert s["id_hallucination"] == 0.0


def test_partial_scores_and_relaxed_case_matching() -> None:
    gold = js([("Emotet", "MALWARE"), ("APT29", "THREAT_ACTOR")], ["T1566", "T1059"])
    pred = js([("emotet", "MALWARE")], ["T1566", "T1486"])
    s = metrics.score([(pred, gold)], LIVE).summary()
    assert s["entity_exact"]["f1"] == 0.0  # case differs
    assert s["entity_relaxed"]["precision"] == 1.0 and s["entity_relaxed"]["recall"] == 0.5
    assert s["technique_micro"]["precision"] == 0.5 and s["technique_micro"]["recall"] == 0.5
    assert s["relation"]["gold"] == 0  # the gold has no relations list: relations are not scored


def test_invalid_output_counts_against_recall_not_the_denominator() -> None:
    gold = js([("Emotet", "MALWARE")], ["T1566"])
    s = metrics.score([("not json at all", gold), (gold, gold)], LIVE).summary()
    assert s["n"] == 2 and s["json_valid"] == 0.5
    assert s["entity_exact"]["recall"] == 0.5 and s["entity_exact"]["precision"] == 1.0


def test_schema_violations_are_invalid_not_crashes() -> None:
    gold = js([], [])
    bad_type = '{"entities":[{"text":"x","type":"ORG"}],"techniques":[]}'
    bad_id = '{"entities":[],"techniques":[{"attack_id":"banana"}]}'
    assert metrics.parse(bad_type) is None and metrics.parse(bad_id) is None and metrics.parse(gold) is not None
    assert metrics.parse('```json\n{"entities":[],"techniques":[]}\n```') is None  # fenced output is not minified JSON


def test_hallucinated_ids_are_counted_against_the_live_set() -> None:
    gold = js([], ["T1566"])
    pred = js([], ["T1566", "T9999"])
    s = metrics.score([(pred, gold)], LIVE).summary()
    assert s["id_hallucination"] == 0.5


def test_macro_f1_weighs_rare_techniques_equally() -> None:
    gold_a, gold_b = js([], ["T1566"]), js([], ["T1486"])
    pairs = [(gold_a, gold_a)] * 9 + [(js([], []), gold_b)]  # the common one always right, the rare one always missed
    s = metrics.score(pairs, LIVE).summary()
    assert s["technique_micro"]["f1"] > 0.9 and s["technique_macro_f1"] == 0.5
