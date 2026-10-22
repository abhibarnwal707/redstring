# Fine-tuning dataset

Built by `make finetune-data` (`src/redstring_cti/extractor/dataset.py`). ATT&CK 20.0, seed 42.

| Split | Examples | From ATT&CK procedures | From AnnoCTR | Distinct documents |
|---|---|---|---|---|
| train | 7,009 | 6,779 | 230 | 956 |
| val | 197 | 150 | 47 | 48 |
| test_annoctr | 78 | 0 | 78 | 29 |
| test_procedures | 600 | 600 | 0 | 63 |

**Documents never straddle splits** (asserted): procedure examples are split by source object (actor, malware or tool), AnnoCTR by the official report split. Identical texts are removed from validation and test if they occur in training.

## Composition

- Training techniques: 612 distinct; per-technique cap 25 on procedure examples (the most frequent technique has hundreds of sentences, the median 7).
- val: 102 distinct techniques, 1 never seen in training.
- test_annoctr: 40 distinct techniques, 1 never seen in training.
- test_procedures: 212 distinct techniques, 1 never seen in training.

Entity types in training: MALWARE 3,729, THREAT_ACTOR 2,730, CAMPAIGN 598, TOOL 577, CVE 5.
Training examples with no entity and no technique (kept as 'empty output' examples): 105.
Text length in characters: train median 94, p95 290, max 1500; AnnoCTR chunks median 1411, p95 1491, max 1500.

## What was dropped or changed

- chunks built: 899
- chunks dropped (unresolvable technique mention): 544
- chunks tainted by an implicit technique mention: 1,859
- entity spans dropped (URL slug): 1
- procedure examples before balancing: 17,173
- procedure train examples removed by the per-technique cap: 8,874
- procedure val/test examples removed: identical text in train: 0
- procedures dropped: source not named in the sentence: 17
- procedures dropped: text length: 446
- sentences longer than a chunk: 2
- technique links: 3,337
- technique links mapped: 30
- technique links unchanged: 3,289
- technique links without a current id: 18
- technique row linked to a non-technique (skipped): 11
- technique spans resolved: 1,068
- technique spans unresolved or ambiguous: 30

(AnnoCTR counts are summed over its train, dev and test splits; dev is used as validation.)

## Design decisions

- Entities carry text and type only (no ATT&CK id); mapping names to graph ids is the entity linker's job in Phase 11.
- No `evidence` field; the schema stays small.
- Two task prompts: ATT&CK procedure examples ask for entities, techniques and relations (their relations are verified); AnnoCTR has no relation labels, so its examples ask only for entities and techniques. This avoids teaching the model that real reports contain no relations.
- TRAM is not used: 'TRAM-Clean' is a cleaning protocol in a paper, not a downloadable dataset, and the raw TRAM labels are noisy.
- AnnoCTR technique ids come from 2021-era ATT&CK links and are mapped to the pinned version through `revoked-by`; chunks with a technique that cannot be mapped are dropped.

## Sources and licences

- MITRE ATT&CK v20 procedure examples (MITRE ATT&CK terms of use).
- AnnoCTR, Lange et al., LREC-COLING 2024, CC BY-SA 4.0 (`github.com/boschresearch/anno-ctr-lrec-coling-2024`). Derived data is released under the same licence if redistributed; the dataset stays private on Kaggle.

## Test sets

`test_annoctr` is the headline test set: real reports, expert-annotated, converted automatically. `test_procedures` is an easy in-distribution check and the only set with verified relations. **`finetune/data/review_sheet.csv` holds 80 test chunks to verify by hand (the playbook asks for a hand-verified test set); until that is done the test labels are the AnnoCTR annotators' labels as converted by this pipeline.**
