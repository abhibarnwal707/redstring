# Baselines on the dev split (INTERIM)

- Same questions, same model, same scorer for every run; only questions answered by every run are compared (paired).
- INTERIM: Text2Cypher is only partly run (Groq daily token cap); only questions answered by gpt-oss-120b for BOTH systems are compared. Re-scored with the current scorer (inline FINAL lines are now parsed).

| Question group | vector_rag-dev acc. | vector_rag-dev F1 | text2cypher-dev acc. | text2cypher-dev F1 |
|---|---|---|---|---|
| aggregation (count) | 0.0% (n=1) | n/a | 100.0% (n=1) | n/a |
| aggregation (ranked) | 0.0% (n=1) | 0.0% | 100.0% (n=1) | 100.0% |
| multi_hop (2-hop) | 0.0% (n=23) | 1.7% | 69.6% (n=23) | 73.4% |
| multi_hop (3-hop) | 0.0% (n=4) | 0.0% | 100.0% (n=4) | 100.0% |
| single_hop | 11.1% (n=27) | 18.0% | 96.3% (n=27) | 96.3% |
| **overall** | 5.4% (n=56) | 9.6% | 85.7% (n=56) | 87.0% |

| Run | Service p50 | Service p95 | Tokens in/out per q | Reference $/q | Cited IDs not in evidence | Errors | Fallbacks |
|---|---|---|---|---|---|---|---|
| vector_rag-dev | 0.8s | 2.5s | 1139/56 | $0.00020 | 0.0% | 0 | 0 |
| text2cypher-dev | 1.5s | 2.8s | 1765/220 | $0.00040 | 0.0% | 0 | 0 |

Questions compared / answered validly per run: vector_rag-dev: 56 of 109, text2cypher-dev: 56 of 56.
