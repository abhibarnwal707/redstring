"""Assemble the fine-tuning dataset (Phase 8): normalise, balance, split by document, validate, write.

Sources
* ATT&CK procedure examples (short sentences, verified relations): split by SOURCE OBJECT, so all sentences
  about one actor or tool stay together; capped per technique because the distribution is heavily skewed.
* AnnoCTR (long real-report chunks, expert annotation): the official train / dev / test document split.

Outputs (finetune/data/, git-ignored): train.jsonl, val.jsonl, test_annoctr.jsonl, test_procedures.jsonl,
review_sheet.csv (chunks to verify by hand). A statistics report goes to evals/results/finetune_dataset.md."""

import argparse
import csv
import hashlib
import logging
import random
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import orjson

from redstring_cti.config import ATTACK_VERSION, RAW_DIR
from redstring_cti.extractor.attack_ids import AttackIds, load_attack_ids
from redstring_cti.extractor.records import Example
from redstring_cti.extractor.schema import SYSTEM_PROMPTS, Extraction
from redstring_cti.extractor.sources import annoctr, attack_procedures

log = logging.getLogger(__name__)

ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = ROOT / "finetune" / "data"
REPORT_PATH = ROOT / "evals" / "results" / "finetune_dataset.md"
ANNOCTR_ROOT = RAW_DIR / "finetune" / "annoctr"
PROC_TRAIN_SHARE, PROC_VAL_SHARE = 0.90, 0.04  # the rest is the procedure test set
CAP_PER_TECHNIQUE = 10
PROC_VAL_MAX, PROC_TEST_MAX = 150, 600
REVIEW_SHEET_SIZE = 80
SEED = 42


@dataclass
class Dataset:
    train: list[Example] = field(default_factory=list)
    val: list[Example] = field(default_factory=list)
    test_annoctr: list[Example] = field(default_factory=list)
    test_procedures: list[Example] = field(default_factory=list)
    notes: Counter[str] = field(default_factory=Counter)

    def splits(self) -> dict[str, list[Example]]:
        return {"train": self.train, "val": self.val, "test_annoctr": self.test_annoctr, "test_procedures": self.test_procedures}


def procedure_split(doc_id: str) -> str:
    """Deterministic, hash-based: independent of file order and stable when data is added."""
    h = int(hashlib.sha1(doc_id.encode()).hexdigest(), 16) / 16**40
    return "train" if h < PROC_TRAIN_SHARE else "val" if h < PROC_TRAIN_SHARE + PROC_VAL_SHARE else "test"


def cap_per_technique(examples: list[Example], cap: int, seed: int = SEED) -> list[Example]:
    """Keep at most `cap` examples per technique (rare techniques keep everything). Deterministic."""
    by_technique: dict[str, list[Example]] = defaultdict(list)
    for e in examples:
        by_technique[e.meta["technique"]].append(e)
    rng = random.Random(seed)
    kept: list[Example] = []
    for technique in sorted(by_technique):
        group = sorted(by_technique[technique], key=lambda e: (e.doc_id, e.text))
        rng.shuffle(group)
        kept += group[:cap]
    return sorted(kept, key=lambda e: (e.doc_id, e.text))


def sample(examples: list[Example], k: int, seed: int = SEED) -> list[Example]:
    pool = sorted(examples, key=lambda e: (e.doc_id, e.text))
    random.Random(seed).shuffle(pool)
    return sorted(pool[:k], key=lambda e: (e.doc_id, e.text))


def drop_text_leaks(train: list[Example], held_out: list[Example]) -> tuple[list[Example], int]:
    """Remove held-out examples whose exact text also occurs in training (identical procedure sentences repeat)."""
    seen = {e.text for e in train}
    kept = [e for e in held_out if e.text not in seen]
    return kept, len(held_out) - len(kept)


def build(bundle: Path, annoctr_root: Path, ids: AttackIds) -> Dataset:
    ds = Dataset()
    procs, drops = attack_procedures.load_examples(bundle, ids)
    ds.notes.update({f"procedures dropped: {k}": v for k, v in drops.items()})
    ds.notes["procedure examples before balancing"] = len(procs)
    by_split: dict[str, list[Example]] = defaultdict(list)
    for e in procs:
        e.split = procedure_split(e.doc_id)
        by_split[e.split].append(e)
    proc_train = cap_per_technique(by_split["train"], CAP_PER_TECHNIQUE)
    ds.notes["procedure train examples removed by the per-technique cap"] = len(by_split["train"]) - len(proc_train)

    annos, stats = annoctr.load_all(annoctr_root, ids)
    ds.notes.update(stats)
    ds.train = sorted(proc_train + [e for e in annos if e.split == "train"], key=lambda e: (e.source, e.doc_id, e.text))
    proc_val, leaked_val = drop_text_leaks(proc_train, by_split["val"])
    proc_test, leaked_test = drop_text_leaks(proc_train, by_split["test"])
    ds.notes["procedure val/test examples removed: identical text in train"] = leaked_val + leaked_test
    ds.val = sample(proc_val, PROC_VAL_MAX) + [e for e in annos if e.split == "val"]
    ds.test_procedures = sample(proc_test, PROC_TEST_MAX)
    ds.test_annoctr = [e for e in annos if e.split == "test"]
    for name, items in ds.splits().items():
        for e in items:
            e.split = "test" if name.startswith("test") else name
    return ds


def validate(ds: Dataset, ids: AttackIds) -> list[str]:
    """Hard checks; returns a list of problems (empty when the dataset is sound)."""
    problems: list[str] = []
    owner: dict[str, str] = {}
    for name, items in ds.splits().items():
        for e in items:
            other = owner.setdefault(e.key, name)
            if other.split("_")[0] != name.split("_")[0] and not (other.startswith("test") and name.startswith("test")):
                problems.append(f"document {e.key} appears in both {other} and {name}")
            if any(t.attack_id not in ids.live for t in e.extraction.techniques):
                problems.append(f"{e.key}: technique not live in ATT&CK {ATTACK_VERSION}")
            if any(en.text not in e.text for en in e.extraction.entities):
                problems.append(f"{e.key}: an entity string is missing from the text")
            if Extraction.from_json(e.extraction.to_json()).to_json() != e.extraction.to_json():
                problems.append(f"{e.key}: target does not round-trip")
    train_docs = {e.key for e in ds.train}
    for name in ("val", "test_annoctr", "test_procedures"):
        shared = train_docs & {e.key for e in ds.splits()[name]}
        if shared:
            problems.append(f"{len(shared)} documents shared between train and {name}")
    train_text = {e.text for e in ds.train}
    for name in ("val", "test_annoctr", "test_procedures"):
        if leaked := [e for e in ds.splits()[name] if e.text in train_text]:
            problems.append(f"{len(leaked)} {name} texts also occur in train")
    return problems


def to_chat(e: Example) -> dict[str, Any]:
    return {
        "id": f"{e.source}:{e.doc_id}:{e.meta.get('chunk', e.meta.get('technique', ''))}",
        "source": e.source,
        "doc_id": e.doc_id,
        "task": e.extraction.task,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPTS[e.extraction.task]},
            {"role": "user", "content": e.text},
            {"role": "assistant", "content": e.extraction.to_json()},
        ],
    }


def write(ds: Dataset, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, items in ds.splits().items():
        (out_dir / f"{name}.jsonl").write_bytes(b"".join(orjson.dumps(to_chat(e)) + b"\n" for e in items))
    review = sample([e for e in ds.test_annoctr if e.extraction.techniques], REVIEW_SHEET_SIZE * 3 // 4) + sample(
        [e for e in ds.test_annoctr if not e.extraction.techniques], REVIEW_SHEET_SIZE // 4
    )
    with (out_dir / "review_sheet.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["id", "doc_id", "text", "entities", "techniques", "verified (y/n)", "corrections"])
        for e in review:
            w.writerow([to_chat(e)["id"], e.doc_id, e.text, orjson.dumps([x.model_dump() for x in e.extraction.entities]).decode(),
                        ",".join(t.attack_id for t in e.extraction.techniques), "", ""])


def _quantiles(values: list[int]) -> str:
    if not values:
        return "-"
    v = sorted(values)
    return f"median {v[len(v) // 2]}, p95 {v[int(len(v) * 0.95)]}, max {v[-1]}"


def render_report(ds: Dataset) -> str:
    rows = []
    for name, items in ds.splits().items():
        by_src = Counter(e.source for e in items)
        rows.append(f"| {name} | {len(items):,} | {by_src.get('attack_procedures', 0):,} | {by_src.get('annoctr', 0):,} | {len({e.key for e in items}):,} |")
    train_techniques = {t.attack_id for e in ds.train for t in e.extraction.techniques}
    lines = [
        "# Fine-tuning dataset",
        "",
        f"Built by `make finetune-data` (`src/redstring_cti/extractor/dataset.py`). ATT&CK {ATTACK_VERSION}, seed {SEED}.",
        "",
        "| Split | Examples | From ATT&CK procedures | From AnnoCTR | Distinct documents |",
        "|---|---|---|---|---|",
        *rows,
        "",
        ("**Documents never straddle splits** (asserted): procedure examples are split by source object (actor, malware or tool), AnnoCTR "
        "by the official report split. Identical texts are removed from validation and test if they occur in training."),
        "",
        "## Composition",
        "",
        (f"- Training techniques: {len(train_techniques)} distinct; per-technique cap {CAP_PER_TECHNIQUE} on procedure examples "
        f"(the most frequent technique has hundreds of sentences, the median 7)."),
    ]
    for name in ("val", "test_annoctr", "test_procedures"):
        techs = {t.attack_id for e in ds.splits()[name] for t in e.extraction.techniques}
        lines.append(f"- {name}: {len(techs)} distinct techniques, {len(techs - train_techniques)} never seen in training.")
    lines += ["", "Entity types in training: " + ", ".join(f"{k} {v:,}" for k, v in Counter(en.type for e in ds.train for en in e.extraction.entities).most_common()) + ".",
              ("Training examples with no entity and no technique (kept as 'empty output' examples): "
              f"{sum(not e.extraction.entities and not e.extraction.techniques for e in ds.train)}."),
              "Text length in characters: train " + _quantiles([len(e.text) for e in ds.train]) + "; AnnoCTR chunks " + _quantiles([len(e.text) for e in ds.train if e.source == 'annoctr']) + ".",
              "", "## What was dropped or changed", ""]
    totals: Counter[str] = Counter()
    for key, value in ds.notes.items():
        totals[key.split(": ", 1)[1] if key.split(":")[0] in ("train", "dev", "test") else key] += value
    lines += [f"- {k}: {v:,}" for k, v in sorted(totals.items())]
    lines += ["", "(AnnoCTR counts are summed over its train, dev and test splits; dev is used as validation.)"]
    lines += [
        "",
        "## Design decisions",
        "",
        "- Entities carry text and type only (no ATT&CK id); mapping names to graph ids is the entity linker's job in Phase 11.",
        "- No `evidence` field; the schema stays small.",
        ("- Two task prompts: ATT&CK procedure examples ask for entities, techniques and relations (their relations are verified); "
        "AnnoCTR has no relation labels, so its examples ask only for entities and techniques. This avoids teaching the model that real "
        "reports contain no relations."),
        "- TRAM is not used: 'TRAM-Clean' is a cleaning protocol in a paper, not a downloadable dataset, and the raw TRAM labels are noisy.",
        "- AnnoCTR technique ids come from 2021-era ATT&CK links and are mapped to the pinned version through `revoked-by`; chunks with a technique that cannot be mapped are dropped.",
        "",
        "## Sources and licences",
        "",
        "- MITRE ATT&CK v20 procedure examples (MITRE ATT&CK terms of use).",
        ("- AnnoCTR, Lange et al., LREC-COLING 2024, CC BY-SA 4.0 (`github.com/boschresearch/anno-ctr-lrec-coling-2024`). "
        "Derived data is released under the same licence if redistributed; the dataset stays private on Kaggle."),
        "",
        "## Test sets",
        "",
        ("`test_annoctr` is the headline test set: real reports, expert-annotated, converted automatically. `test_procedures` is an easy "
        "in-distribution check and the only set with verified relations. **`finetune/data/review_sheet.csv` holds 80 test chunks "
        "to verify by hand (the playbook asks for a hand-verified test set); until that is done the test labels are the AnnoCTR "
        "annotators' labels as converted by this pipeline.**"),
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the fine-tuning dataset.")
    parser.add_argument("--out", type=Path, default=OUT_DIR)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    bundle = RAW_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"
    ids = load_attack_ids(bundle)
    ds = build(bundle, ANNOCTR_ROOT, ids)
    problems = validate(ds, ids)
    if problems:
        raise SystemExit("dataset is not sound:\n  " + "\n  ".join(problems[:20]))
    write(ds, args.out)
    REPORT_PATH.write_text(render_report(ds))
    for name, items in ds.splits().items():
        log.info("%-16s %6d examples", name, len(items))
    log.info("wrote %s and %s", args.out, REPORT_PATH)


if __name__ == "__main__":
    main()
