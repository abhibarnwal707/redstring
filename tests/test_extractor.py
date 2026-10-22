import hashlib
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

import orjson
import pytest
from pydantic import ValidationError

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.extractor import dataset
from redstring_cti.extractor.attack_ids import (
    AttackIds,
    load_attack_ids,
    technique_id_from_url,
)
from redstring_cti.extractor.records import Example
from redstring_cti.extractor.schema import (
    SYSTEM_PROMPTS,
    Entity,
    Extraction,
    Relation,
    Technique,
)
from redstring_cti.extractor.sources import annoctr, attack_procedures

REPO = Path(__file__).resolve().parents[1]
BUNDLE = RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
ANNOCTR = RAW_DIR / "finetune" / "annoctr"


# ------------------------------------------------------------------ schema
def ext(entities: list[tuple[str, str]], techniques: list[str], relations: list[tuple[str, str, str]] | None = None) -> Extraction:
    return Extraction(
        entities=[Entity(text=t, type=ty) for t, ty in entities],  # type: ignore[arg-type]
        techniques=[Technique(attack_id=i) for i in techniques],
        relations=None if relations is None else [Relation(head=h, relation=r, tail=t) for h, r, t in relations],  # type: ignore[arg-type]
    )


def test_serialisation_is_minified_ordered_and_round_trips() -> None:
    e = ext([("APT29", "THREAT_ACTOR")], ["T1566.001"], [("APT29", "USES", "T1566.001")])
    assert e.to_json() == '{"entities":[{"text":"APT29","type":"THREAT_ACTOR"}],"techniques":[{"attack_id":"T1566.001"}],"relations":[{"head":"APT29","relation":"USES","tail":"T1566.001"}]}'
    assert Extraction.from_json(e.to_json()).to_json() == e.to_json()
    assert "relations" not in ext([], []).to_json()  # not requested: the key is absent, not an empty list
    assert ext([], [], []).task == "full" and ext([], []).task == "entities_techniques" and set(SYSTEM_PROMPTS) == {"full", "entities_techniques"}


def test_canonical_form_is_a_total_order_and_deduplicates() -> None:
    a = ext([("REvil", "MALWARE"), ("Revil", "MALWARE"), ("APT29", "THREAT_ACTOR"), ("APT29", "THREAT_ACTOR")], ["T1486", "T1059", "T1486"])
    b = ext([("Revil", "MALWARE"), ("APT29", "THREAT_ACTOR"), ("REvil", "MALWARE")], ["T1059", "T1486"])
    assert a.to_json() == b.to_json()  # equal regardless of input order, even for names that differ only by case
    assert [t.attack_id for t in a.canonical().techniques] == ["T1059", "T1486"]


@pytest.mark.parametrize(
    "build",
    [
        lambda: Entity(text="", type="MALWARE"),
        lambda: Entity(text=" padded ", type="MALWARE"),
        lambda: Entity(text="x", type="ORGANISATION"),  # type: ignore[arg-type]
        lambda: Technique(attack_id="T15"),
        lambda: Technique(attack_id="TA0001"),
        lambda: ext([("APT29", "THREAT_ACTOR")], [], [("Other", "USES", "T1566")]),  # head is not an extracted entity
        lambda: ext([("APT29", "THREAT_ACTOR")], [], [("APT29", "USES", "banana")]),  # tail is nothing known
        lambda: ext([("APT29", "THREAT_ACTOR")], [], [("APT29", "LIKES", "T1566")]),  # type: ignore[arg-type]
    ],
)
def test_schema_rejects_bad_data(build: Any) -> None:
    with pytest.raises((ValidationError, ValueError)):
        build()


def test_relations_may_target_a_cve() -> None:
    assert ext([("APT29", "THREAT_ACTOR"), ("CVE-2019-19781", "CVE")], [], [("APT29", "EXPLOITS", "CVE-2019-19781")]).relations


# ------------------------------------------------------------------ ATT&CK id history
def stix(kind: str, ident: str, ext_id: str, **kw: Any) -> dict[str, Any]:
    return {"type": kind, "id": f"{kind}--{ident}", "name": kw.pop("name", ext_id),
            "external_references": [{"source_name": "mitre-attack", "external_id": ext_id}], **kw}


def synthetic_bundle(tmp_path: Path) -> Path:
    objs = [
        stix("attack-pattern", "t1", "T9101", name="Run Commands"), stix("attack-pattern", "t2", "T9101.001", name="Sub Thing"),
        stix("attack-pattern", "t3", "T9102", revoked=True), stix("attack-pattern", "t4", "T9103", x_mitre_deprecated=True),
        {"type": "relationship", "id": "relationship--rb", "relationship_type": "revoked-by", "source_ref": "attack-pattern--t3", "target_ref": "attack-pattern--t2"},
        stix("intrusion-set", "g1", "G9101", name="TestBear", aliases=["TestBear", "Cozy Test"]),
        stix("tool", "s1", "S9101", name="ToolX"), stix("malware", "s2", "S9102", name="MalY"), stix("campaign", "c1", "C9101", name="Operation Test"),
        stix("intrusion-set", "g2", "G9102", name="OldBear", revoked=True),
        {"type": "relationship", "id": "relationship--1", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--t1",
         "description": "[TestBear](https://attack.mitre.org/groups/G9101) used [ToolX](https://attack.mitre.org/software/S9101) to run commands, "
                        "then [Sub Thing](https://attack.mitre.org/techniques/T9101/001) and the old [T9102](https://attack.mitre.org/techniques/T9102).(Citation: Foo (2020))"},
        {"type": "relationship", "id": "relationship--2", "relationship_type": "uses", "source_ref": "malware--s2", "target_ref": "attack-pattern--t2",
         "description": "MalY can run commands on the infected host and report back to its operator."},  # source named plainly, not linked
        {"type": "relationship", "id": "relationship--3", "relationship_type": "uses", "source_ref": "campaign--c1", "target_ref": "attack-pattern--t1",
         "description": "During [Operation Test](https://attack.mitre.org/campaigns/C9101), [MalY](https://attack.mitre.org/software/S9102) ran commands."},
        {"type": "relationship", "id": "relationship--4", "relationship_type": "uses", "source_ref": "intrusion-set--g2", "target_ref": "attack-pattern--t1",
         "description": "[OldBear](https://attack.mitre.org/groups/G9102) used something."},  # revoked source
        {"type": "relationship", "id": "relationship--5", "relationship_type": "uses", "source_ref": "intrusion-set--g1", "target_ref": "attack-pattern--t1", "description": "Too short."},
        {"type": "relationship", "id": "relationship--6", "relationship_type": "uses", "source_ref": "tool--s1", "target_ref": "attack-pattern--t1",
         "description": "An unrelated sentence that never mentions its source object at all, so no relation can be formed."},
    ]
    path = tmp_path / "bundle.json"
    path.write_bytes(orjson.dumps({"type": "bundle", "objects": objs}))
    return path


def test_attack_id_history(tmp_path: Path) -> None:
    ids = load_attack_ids(synthetic_bundle(tmp_path))
    assert ids.live == {"T9101", "T9101.001"} and ids.successor == {"T9102": "T9101.001"}
    assert ids.current("T9101") == "T9101" and ids.current("T9102") == "T9101.001"
    assert ids.current("T9103") is None and ids.current("T0000") is None  # deprecated with no successor / unknown
    loop = AttackIds(live=set(), successor={"A": "B", "B": "A"})
    assert loop.current("A") is None  # a cycle must not hang


def test_technique_id_from_url() -> None:
    assert technique_id_from_url("https://attack.mitre.org/techniques/T1055/012") == "T1055.012"
    assert technique_id_from_url("https://attack.mitre.org/techniques/T1486") == "T1486"
    assert technique_id_from_url("https://attack.mitre.org/software/S0002") is None


def test_real_bundle_maps_old_ids() -> None:
    if not BUNDLE.exists():
        pytest.skip("run `make download` first")
    ids = load_attack_ids(BUNDLE)
    assert ids.current("T1086") == "T1059.001" and ids.current("T1193") == "T1566.001" and ids.current("T1064") is None


# ------------------------------------------------------------------ ATT&CK procedure examples
def test_procedure_examples_get_entities_techniques_and_a_verified_relation(tmp_path: Path) -> None:
    bundle = synthetic_bundle(tmp_path)
    examples, drops = attack_procedures.load_examples(bundle, load_attack_ids(bundle))
    by_text = {e.text: e for e in examples}
    first = next(e for t, e in by_text.items() if t.startswith("TestBear used"))
    assert "(Citation" not in first.text and "](" not in first.text
    assert first.extraction.entities == [Entity(text="TestBear", type="THREAT_ACTOR"), Entity(text="ToolX", type="TOOL")]
    assert [t.attack_id for t in first.extraction.techniques] == ["T9101", "T9101.001"]  # the sentence's technique + a linked one; T9102 mapped to T9101.001
    assert first.extraction.relations == [Relation(head="TestBear", relation="USES", tail="T9101")]
    assert first.doc_id == "intrusion-set--g1"
    plain = next(e for e in examples if e.text.startswith("MalY can run"))
    assert plain.extraction.entities == [Entity(text="MalY", type="MALWARE")]  # unlinked source found by name
    camp = next(e for e in examples if e.text.startswith("During Operation Test"))
    assert {(x.text, x.type) for x in camp.extraction.entities} == {("Operation Test", "CAMPAIGN"), ("MalY", "MALWARE")}
    assert camp.extraction.relations == [Relation(head="Operation Test", relation="USES", tail="T9101")]  # the campaign is the source
    assert len(examples) == 3
    assert drops["text length"] == 1 and drops["source not named in the sentence"] == 1 and drops["not live or no description"] >= 1


def test_every_procedure_entity_string_is_in_its_sentence_on_real_data() -> None:
    if not BUNDLE.exists():
        pytest.skip("run `make download` first")
    examples, _ = attack_procedures.load_examples(BUNDLE, load_attack_ids(BUNDLE))
    assert len(examples) > 15000
    assert all(en.text in e.text for e in examples for en in e.extraction.entities)
    assert all(e.extraction.relations and e.extraction.relations[0].head in {en.text for en in e.extraction.entities} for e in examples)


# ------------------------------------------------------------------ AnnoCTR conversion
def test_bio_spans() -> None:
    assert annoctr.bio_spans(["O", "B-MALWARE", "I-MALWARE", "O", "B-GROUP", "B-TOOL"]) == [(1, 3, "MALWARE"), (4, 5, "GROUP"), (5, 6, "TOOL")]
    assert annoctr.bio_spans(["I-TOOL", "I-TOOL", "O"]) == [(0, 2, "TOOL")]  # a span may start with I- in noisy data
    assert annoctr.bio_spans(["B-A", "I-B"]) == [(0, 1, "A"), (1, 2, "B")]
    assert annoctr.bio_spans([]) == []


def test_surface_form_comes_from_the_sentence_not_the_tokens() -> None:
    sentence = "The Cobalt Strike beacon (used by APT29) called out."
    assert annoctr.surface(sentence, ["Cobalt", "Strike"], 0, 2) == "Cobalt Strike"
    assert annoctr.surface(sentence, ["The", "Cobalt", "Strike", "beacon"], 1, 3) == "Cobalt Strike"
    assert annoctr.surface("see the C2 server", ["C2"], 0, 1) == "C2"
    assert annoctr.surface(sentence, ["Nothing"], 0, 1) is None and annoctr.surface(sentence, [], 0, 0) is None


def ner_row(doc: str, idx: int, text: str, ce: dict[int, str] | None = None, ci: dict[int, str] | None = None) -> dict[str, Any]:
    tokens = text.replace(".", " .").split()
    def tags(marks: dict[int, str] | None) -> list[str]:
        out = ["O"] * len(tokens)
        for i, kind in (marks or {}).items():
            out[i] = f"B-{kind}"
        return out
    return {"id": f"{doc}__s{idx:04d}", "tokens": tokens, "text": text, "ce_tags": tags(ce), "ci_tags": tags(ci)}


def write_annoctr(root: Path, rows: list[dict[str, Any]], links: list[dict[str, Any]], split: str = "train") -> None:
    for sub in ("ner_json", "linking_mitre_only"):
        (root / "AnnoCTR" / sub).mkdir(parents=True, exist_ok=True)
    (root / "AnnoCTR" / "ner_json" / f"{split}.json").write_bytes(b"\n".join(orjson.dumps(r) for r in rows) + b"\n\n")
    (root / "AnnoCTR" / "linking_mitre_only" / f"{split}.jsonl").write_bytes(b"\n\n".join(orjson.dumps(r) for r in links) + b"\n")


def test_annoctr_chunks_resolve_techniques_and_drop_unresolvable_ones(tmp_path: Path) -> None:
    ids = AttackIds(live={"T1486", "T1059.001"}, successor={"T1086": "T1059.001"})
    link = lambda mention, url, kind="TECHNIQUE": {"entity_type": kind, "label_link": url, "mention": mention, "document": "doc1"}
    rows = [
        ner_row("doc1", 0, "TestBear deployed Trickbot.", ce={0: "GROUP", 2: "MALWARE"}),
        ner_row("doc1", 1, "They encrypted files using ransomware and CVE-2021-44228 was exploited.", ce={4: "TECHNIQUE"}),  # token 4 is "ransomware"
        ner_row("doc1", 2, "-----------------"),  # a separator contributes nothing
        ner_row("doc1", 3, "Attackers ran powershell scripts.", ce={2: "TECHNIQUE"}),
        ner_row("doc2", 0, "Something mysterious happened here.", ci={1: "TECHNIQUE"}),  # no linking row at all
    ]
    links = [
        link("ransomware", "https://attack.mitre.org/techniques/T1486"),
        link("powershell", "https://attack.mitre.org/techniques/T1086"),  # revoked: mapped to T1059.001
        link("Trickbot", "https://attack.mitre.org/software/S0266", "MALWARE"),  # not a technique row: ignored
        link("Netwire", "https://attack.mitre.org/software/S0332"),  # technique-typed row with a software link: skipped
    ]
    write_annoctr(tmp_path, rows, links)
    stats: Counter[str] = Counter()
    out = annoctr.load_split(tmp_path, "train", ids, stats)
    assert [e.doc_id for e in out] == ["doc1"]  # doc2's chunk had an unresolvable technique and was dropped
    chunk = out[0]
    assert chunk.split == "train" and chunk.extraction.task == "entities_techniques"
    assert {(e.text, e.type) for e in chunk.extraction.entities} == {("TestBear", "THREAT_ACTOR"), ("Trickbot", "MALWARE"), ("CVE-2021-44228", "CVE")}
    assert [t.attack_id for t in chunk.extraction.techniques] == ["T1059.001", "T1486"]
    assert "-----" not in chunk.text and chunk.text.count("\n") == 2
    assert stats["train: chunks dropped (unresolvable technique mention)"] == 1 and stats["train: technique links mapped"] == 1


def test_annoctr_drops_chunks_with_implicit_or_ambiguous_techniques(tmp_path: Path) -> None:
    ids = AttackIds(live={"T1486", "T1566"})
    link = lambda mention, url: {"entity_type": "TECHNIQUE", "label_link": url, "mention": mention, "document": "d"}
    rows = [
        ner_row("d", 0, "They encrypted everything."),
        ner_row("d", 1, "x" * 1500 + " the crew encrypted data.", ce={}, ci={}),
        ner_row("d", 2, "Stolen mail was used to phish staff with phishing lures.", ci={1: "TECHNIQUE"}),  # implicit
    ]
    write_annoctr(tmp_path, rows, [link("phish", "https://attack.mitre.org/techniques/T1566")])
    out = annoctr.load_split(tmp_path, "train", ids, Counter())
    assert all("phish" not in e.text for e in out)  # the chunk with the implicit mention is gone
    ambiguous = [ner_row("d", 0, "Attackers encrypt files.", ce={2: "TECHNIQUE"})]
    write_annoctr(tmp_path, ambiguous, [link("files", "https://attack.mitre.org/techniques/T1486"), link("files", "https://attack.mitre.org/techniques/T1566")])
    assert annoctr.load_split(tmp_path, "train", ids, Counter()) == []  # one phrase, two ids: dropped


def test_annoctr_drops_an_unbreakable_blob_sentence(tmp_path: Path) -> None:
    """Regression: two base64 images became 66K and 133K character 'chunks' in validation and broke generation."""
    rows = [ner_row("img", 0, "A normal opening sentence about the report."), ner_row("img", 1, "![](data:image/png;base64," + "A" * 60000 + ")"),
            ner_row("img", 2, "A closing sentence that is fine.")]
    write_annoctr(tmp_path, rows, [{"entity_type": "GROUP", "label_link": "x", "mention": "x", "document": "img"}])
    out = annoctr.load_split(tmp_path, "train", AttackIds(live=set()), Counter())
    assert all(len(e.text) <= annoctr.MAX_CHUNK_CHARS for e in out) and not any("base64" in e.text for e in out)


def test_validate_rejects_an_oversized_text() -> None:
    ds, ids = tiny_dataset()
    ds.val.append(example("big", "X " + "y" * 5000))
    assert any("exceeds the chunk limit" in p for p in dataset.validate(ds, ids))


def test_annoctr_splits_long_documents_into_bounded_chunks(tmp_path: Path) -> None:
    sentence = "The operators kept using the same infrastructure for many months in a row." * 2  # about 150 characters
    rows = [ner_row("long", i, sentence) for i in range(30)]
    write_annoctr(tmp_path, rows, [{"entity_type": "GROUP", "label_link": "x", "mention": "x", "document": "long"}], split="dev")
    out = annoctr.load_split(tmp_path, "dev", AttackIds(live=set()), Counter())
    assert len(out) > 2 and all(len(e.text) <= annoctr.MAX_CHUNK_CHARS for e in out) and {e.split for e in out} == {"val"}
    assert sum(e.text.count("\n") + 1 for e in out) == 30  # every sentence is in exactly one chunk


# ------------------------------------------------------------------ dataset assembly
def example(doc: str, text: str, technique: str = "T1486", source: str = "attack_procedures", **kw: Any) -> Example:
    return Example(doc_id=doc, text=text, extraction=ext([("X", "MALWARE")], [technique]), source=source, meta={"technique": technique}, **kw)


def test_procedure_split_is_deterministic_and_close_to_the_requested_shares() -> None:
    docs = [f"intrusion-set--{i}" for i in range(4000)]
    counts = Counter(dataset.procedure_split(d) for d in docs)
    assert counts == Counter(dataset.procedure_split(d) for d in reversed(docs))
    assert abs(counts["train"] / 4000 - 0.90) < 0.02 and abs(counts["val"] / 4000 - 0.04) < 0.01 and counts["test"] > 100


def test_cap_per_technique_keeps_rare_techniques_whole_and_is_reproducible() -> None:
    many = [example(f"d{i}", f"X sentence {i}", "T1105") for i in range(50)]
    rare = [example("r", "X rare one", "T1999"), example("r2", "X rare two", "T1999")]
    kept = dataset.cap_per_technique(many + rare, cap=10)
    assert Counter(e.meta["technique"] for e in kept) == {"T1105": 10, "T1999": 2}
    assert [e.text for e in kept] == [e.text for e in dataset.cap_per_technique(list(reversed(many + rare)), cap=10)]


def test_text_leaks_are_removed_from_held_out_sets() -> None:
    train = [example("a", "X identical sentence."), example("b", "X other sentence.")]
    kept, dropped = dataset.drop_text_leaks(train, [example("c", "X identical sentence."), example("d", "X brand new sentence.")])
    assert [e.text for e in kept] == ["X brand new sentence."] and dropped == 1


def tiny_dataset() -> tuple[dataset.Dataset, AttackIds]:
    ids = AttackIds(live={"T1486", "T1105"})
    ds = dataset.Dataset(train=[example("a", "X train one"), example("b", "X train two")], val=[example("c", "X val one")],
                         test_annoctr=[example("r", "X report", source="annoctr")], test_procedures=[example("e", "X test one")])
    return ds, ids


def test_validation_accepts_a_sound_dataset_and_rejects_planted_problems() -> None:
    ds, ids = tiny_dataset()
    assert dataset.validate(ds, ids) == []
    ds.test_procedures.append(example("a", "X a different sentence"))  # same document as a training example
    assert any("document" in p for p in dataset.validate(ds, ids))
    ds, ids = tiny_dataset()
    ds.val.append(example("z", "X train one"))  # identical text in train and val
    assert any("also occur in train" in p for p in dataset.validate(ds, ids))
    ds, ids = tiny_dataset()
    ds.train.append(example("q", "X bad technique", technique="T9999"))
    assert any("not live" in p for p in dataset.validate(ds, ids))
    ds, ids = tiny_dataset()
    ds.train.append(Example(doc_id="m", text="no entity here", extraction=ext([("Missing", "MALWARE")], []), source="annoctr"))
    assert any("missing from the text" in p for p in dataset.validate(ds, ids))


def test_chat_rows_carry_the_task_prompt_and_a_parseable_target() -> None:
    full = example("a", "X uses T1486 here")
    full.extraction = ext([("X", "MALWARE")], ["T1486"], [("X", "USES", "T1486")])
    row = dataset.to_chat(full)
    assert [m["role"] for m in row["messages"]] == ["system", "user", "assistant"] and row["task"] == "full"
    assert row["messages"][0]["content"] == SYSTEM_PROMPTS["full"] and Extraction.from_json(row["messages"][2]["content"]) == full.extraction.canonical()
    assert dataset.to_chat(example("b", "X"))["messages"][0]["content"] == SYSTEM_PROMPTS["entities_techniques"]


# ------------------------------------------------------------------ the real dataset
needs_data = pytest.mark.skipif(not (BUNDLE.exists() and ANNOCTR.exists()), reason="needs the downloaded ATT&CK bundle and the AnnoCTR clone")


@needs_data
def test_real_dataset_is_sound_and_sized_as_planned() -> None:
    ids = load_attack_ids(BUNDLE)
    ds = dataset.build(BUNDLE, ANNOCTR, ids)
    assert dataset.validate(ds, ids) == []
    assert 3000 <= len(ds.train) <= 8000 and 150 <= len(ds.val) <= 400 and len(ds.test_annoctr) > 50 and len(ds.test_procedures) == 600
    assert {e.source for e in ds.test_annoctr} == {"annoctr"} and {e.source for e in ds.test_procedures} == {"attack_procedures"}
    assert len({t.attack_id for e in ds.train for t in e.extraction.techniques}) > 500  # the long tail is still represented
    train_docs = {e.doc_id for e in ds.train if e.source == "annoctr"}
    assert not train_docs & {e.doc_id for e in ds.test_annoctr + ds.val}  # report documents are disjoint


@needs_data
def test_building_twice_with_different_hash_seeds_gives_identical_files(tmp_path: Path) -> None:
    """Regression: names differing only by case once made the sort depend on Python's per-process string hashing."""
    digests = []
    for seed in ("1", "2"):
        out = tmp_path / seed
        subprocess.run([sys.executable, "-c", (f"from pathlib import Path; from redstring_cti.extractor import dataset as d; "
                        f"ids = d.load_attack_ids(d.RAW_DIR / 'enterprise-attack-{ATTACK_VERSION}.json'); "
                        f"ds = d.build(d.RAW_DIR / 'enterprise-attack-{ATTACK_VERSION}.json', d.ANNOCTR_ROOT, ids); d.write(ds, Path({str(out)!r}))")],
                       check=True, cwd=REPO, env={"PYTHONHASHSEED": seed, "PATH": "/usr/bin:/bin", "HOME": str(Path.home())}, capture_output=True)
        digests.append(hashlib.sha256(b"".join((out / f).read_bytes() for f in sorted(p.name for p in out.iterdir()))).hexdigest())
    assert digests[0] == digests[1]
