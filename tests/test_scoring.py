import pytest

from redstring_cti.gold.models import GoldQuestion
from redstring_cti.scoring import (
    extract_ids,
    normalise_number,
    parse_final,
    prf,
    score_question,
)


def q(style: str = "list", ids: list[str] | None = None, values: list[str] | None = None, qtype: str = "single_hop", text: str = "Which things relate to T1566?") -> GoldQuestion:
    unans = style == "not_found"
    return GoldQuestion(
        id="q001", question=text, type="unanswerable" if unans else qtype, hops=0 if unans else 1,  # type: ignore[arg-type]
        answer_style=style, gold_ids=ids or [], gold_values=values or [], gold_cypher="RETURN 1", split="dev",  # type: ignore[arg-type]
    )


def test_extract_ids_finds_every_kind_once_in_order() -> None:
    text = "T1566.001 (TA0001) by G0016 using S0154; M1017, C0024, CAPEC-163, CWE-451, CVE-2024-38112, T1566.001 again"
    assert extract_ids(text) == ["T1566.001", "TA0001", "G0016", "S0154", "M1017", "C0024", "CAPEC-163", "CWE-451", "CVE-2024-38112"]
    assert extract_ids("scores like T15660 or XT1566 or CWE-ABC are not ids") == []


@pytest.mark.parametrize(
    ("text", "kind", "payload"),
    [
        ("Answer.\nFINAL: M1017, M1049", "ids", ["M1017", "M1049"]),
        ("**FINAL:** M1017", "ids", ["M1017"]),
        ("final: 1,234", "number", "1234"),
        ("FINAL: 66.0", "number", "66"),
        ("FINAL: NOT_FOUND", "not_found", None),
        ("FINAL: not found", "not_found", None),
        ("no final line, mentions T1566", "none", None),
        ("FINAL: first\nFINAL: M1017", "ids", ["M1017"]),  # the last FINAL line wins
    ],
)
def test_parse_final(text: str, kind: str, payload: object) -> None:
    f = parse_final(text)
    assert f.kind == kind
    assert (f.ids if kind == "ids" else f.number) == payload or kind in ("none", "not_found")


def test_prf() -> None:
    assert prf(["a", "b"], ["a", "b"]) == (1.0, 1.0, 1.0)
    p, r, f = prf(["a", "x"], ["a", "b"])
    assert (p, r) == (0.5, 0.5) and f == 0.5
    assert prf([], ["a"]) == (0.0, 0.0, 0.0)


def test_list_scoring_uses_the_final_line_not_the_prose() -> None:
    gold = q(ids=["M1017", "M1049"])
    text = "Related: T1566 and also M1031 are mentioned.\nFINAL: M1017, M1049"
    s = score_question(gold, text)
    assert s["correct"] and s["f1"] == 1.0 and s["predicted"] == ["M1017", "M1049"]


def test_threshold_is_f1_at_least_point_eight() -> None:
    gold = q(ids=["M1", "M2", "M3", "M4", "M5"][:0] or ["M1017", "M1018", "M1019", "M1020", "M1021"])
    four_of_five = score_question(gold, "FINAL: M1017, M1018, M1019, M1020")
    assert four_of_five["f1"] == pytest.approx(8 / 9) and four_of_five["correct"]
    three_of_five = score_question(gold, "FINAL: M1017, M1018, M1019")
    assert three_of_five["f1"] == pytest.approx(0.75) and not three_of_five["correct"]


def test_missing_final_line_falls_back_to_cited_ids() -> None:
    s = score_question(q(ids=["M1017"]), "The mitigation is M1017.")
    assert s["correct"] and s["final_kind"] == "none"


def test_saying_not_found_on_an_answerable_question_scores_zero() -> None:
    s = score_question(q(ids=["M1017"]), "FINAL: NOT_FOUND")
    assert not s["correct"] and s["f1"] == 0.0 and s["said_not_found"]


def test_ranked_list_reports_order_separately() -> None:
    gold = q(style="ranked_list", ids=["T1", "T2"][:0] or ["T1105", "T1204.002"], qtype="aggregation")
    right = score_question(gold, "FINAL: T1105, T1204.002")
    swapped = score_question(gold, "FINAL: T1204.002, T1105")
    assert right["order_exact"] and swapped["correct"] and not swapped["order_exact"]


def test_count_scoring() -> None:
    gold = q(style="count", values=["1234"], qtype="aggregation", text="How many things are there?")
    assert score_question(gold, "There are 1,234.\nFINAL: 1234")["correct"]
    assert score_question(gold, "FINAL: 1,234.0")["correct"]
    assert not score_question(gold, "FINAL: 1235")["correct"]
    assert score_question(gold, "I count 1234 of them")["correct"]  # no FINAL line: last number


def test_unanswerable_scoring() -> None:
    gold = q(style="not_found", text="What is the EPSS score of CVE-2024-38112?")
    assert score_question(gold, "I cannot find it.\nFINAL: NOT_FOUND")["correct"]
    assert score_question(gold, "This is not found in the knowledge graph.")["correct"]
    assert not score_question(gold, "The score is 0.5.\nFINAL: 0.5")["correct"]
    assert not score_question(gold, "FINAL: T1566")["correct"]


def test_unsupported_ids_need_evidence_and_ignore_ids_in_the_question() -> None:
    gold = q(ids=["M1017"], text="Which mitigations apply to T1566?")
    s = score_question(gold, "T1566 is mitigated by M1017 and by M9999.\nFINAL: M1017", evidence_ids={"M1017"})
    assert s["unsupported_ids"] == ["M9999"]  # T1566 is in the question, M1017 in the evidence
    assert score_question(gold, "M1017", evidence_ids=None)["unsupported_ids"] == []


def test_normalise_number() -> None:
    assert [normalise_number(x) for x in ("1,234", "66.0", "3.5", "007")] == ["1234", "66", "3.5", "7"]
