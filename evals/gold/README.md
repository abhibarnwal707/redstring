# Gold evaluation set

150 questions with answers computed from the knowledge graph. Built before any retrieval code so the
questions do not drift toward what the system already handles.

| File | What it is |
|---|---|
| `questions.jsonl` | The set (one JSON object per line, validated by `redstring_cti.gold.models.GoldQuestion`) |
| `build_info.json` | Graph counts and source versions the answers were computed from |
| source of the questions | `src/redstring_cti/gold/spec.py` (question text + Cypher); builder: `make gold` |

## How answers are made
Every question stores a `gold_cypher`. `make gold` runs it against the live graph and stores the result as
`gold_ids` (or `gold_values` for counts). Nothing is typed by hand. `tests/test_gold.py` re-runs all 150
queries, so a graph reload or an NVD update that changes an answer fails the test instead of silently
invalidating results. After an intentional graph change: `make gold`, review `git diff evals/gold`, commit.

## Mix (120 dev / 30 test)
| Type | Count | Test | Answer style |
|---|---|---|---|
| single_hop | 40 | 8 | `list` |
| multi_hop (2 / 3 / 4 hops: 37 / 17 / 6) | 60 | 12 (7 / 3 / 2) | `list` |
| aggregation | 25 | 5 | 13 `ranked_list` (top-N, tie-free at the cut-off), 12 `count` |
| semantic (fuzzy, no ids in the question) | 15 | 3 | `list`, judgement-based gold |
| unanswerable | 10 | 2 | `not_found`; the Cypher proves the graph has no answer |

12 questions are about ATT&CK v20 AI techniques (prompt injection, AI services, ...); 4 are in the test set.
The test split is seeded (42) and stratified by type, hop count and answer style.

## Schema
`id`, `question`, `type`, `hops`, `answer_style` (`list` | `ranked_list` | `count` | `not_found`), `gold_ids`,
`gold_values`, `gold_cypher`, `precondition_cypher` (unanswerable: the entity exists), `split`, `tags`, `notes`.

## Rules for using it
1. Iterate on the 120 `dev` questions only. **Do not read failures on the 30 `test` questions** while tuning;
   run them once at the end of Phase 7.
2. Score `list` by ID precision/recall/F1 (correct when F1 >= 0.8), `ranked_list` by set F1 plus order,
   `count` by exact number, `not_found` by whether the answer says the information is not in the graph.
3. The ID extractor must also match campaigns (`C0024`) and use word boundaries.

## Limits (state these in the README)
* Gold answers are what the **graph** contains. The benchmark measures retrieval and reasoning over this
  graph, not whether an answer is useful to a working analyst.
* Chain questions (Technique/Group -> CAPEC -> CWE -> CVE) are worded as weakness-level associations, never
  "the group used this CVE"; only about a quarter of techniques have a CAPEC link at all.
* Semantic questions have a judgement-based gold set; a defensible answer outside it scores as a miss.
* Ambiguity is deliberate in a few places (two techniques are both named "Spearphishing Attachment").
* The set is small: with 30 test questions one question is 3.3 points, so report intervals, not just means.
