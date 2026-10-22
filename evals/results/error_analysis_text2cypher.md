# Text2Cypher baseline: where it fails (dev questions only)

109 dev questions, gpt-oss-120b, 87 correct (79.8%), 22 wrong. Test questions were not looked at.

| Failure | Count | Where |
|---|---|---|
| Replied NOT_FOUND although the graph has the answer | 8 | 5 multi-hop through CAPEC/CWE, 3 semantic |
| Missing items (low recall) | 5 | semantic and set-intersection questions |
| Mixed errors | 3 | set intersections, CAPEC lists |
| Completely wrong set | 2 | wrong entity |
| Right items plus extras | 2 | semantic |
| Answered an unanswerable question | 2 | invented an answer instead of NOT_FOUND |

## What the failures have in common
- **Entity ids written from memory.** Without an entity-resolution step the model puts ids in the Cypher that it recalls from training. Five of the nine multi-hop failures use a wrong or invented group id: "Andariel and LAPSUS$" became `G0138` and `G0139`, and "attack patterns mapped to techniques used by Andariel" queried `G0016`, which is APT29. The query is valid Cypher and returns confident but wrong rows. This is the gap the agent's `resolve_entity` step is built to close.
- **CAPEC and CWE paths return nothing.** Five multi-hop questions that route through CAPEC to CWE got empty results and the model answered NOT_FOUND. These need a metapath template (`find_paths`), which the agent has and a bare Text2Cypher prompt does not.
- **Semantic questions are judged against a fuzzy gold list** (10 of 12 wrong); vector search did better here (33% against 17%). These questions are hard for any graph method and are reported separately.
- **Two unanswerable questions got an answer.** The model produced a plausible one instead of saying the graph lacks the data.

## What this predicts for the agent (a hypothesis, to be tested by `make eval-agent`)
Entity resolution and the path template should fix the multi-hop failures. The semantic questions and the unanswerable ones will not improve unless the agent's routing does.
