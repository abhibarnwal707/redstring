# Baseline comparison

- Same questions, same model, same scorer for every run; only questions answered by every run are compared (paired).

| Question group | vector_rag-dev acc. | vector_rag-dev F1 | text2cypher-dev acc. | text2cypher-dev F1 |
|---|---|---|---|---|
| aggregation (count) | 0.0% (n=9) | n/a | 100.0% (n=9) | n/a |
| aggregation (ranked) | 0.0% (n=9) | 0.0% | 100.0% (n=9) | 100.0% |
| multi_hop (2-hop) | 0.0% (n=28) | 1.4% | 71.4% (n=28) | 74.5% |
| multi_hop (3-hop) | 0.0% (n=13) | 0.0% | 92.3% (n=13) | 92.3% |
| multi_hop (4-hop) | 0.0% (n=3) | 0.0% | 100.0% (n=3) | 100.0% |
| semantic | 33.3% (n=12) | 49.0% | 16.7% (n=12) | 46.2% |
| single_hop | 11.1% (n=27) | 18.0% | 96.3% (n=27) | 96.3% |
| unanswerable | 100.0% (n=8) | n/a | 75.0% (n=8) | n/a |
| **overall** | 13.8% (n=109) | 12.1% | 79.8% (n=109) | 83.1% |

| Run | Service p50 | Service p95 | Tokens in/out per q | Reference $/q | Cited IDs not in evidence | Errors | Fallbacks |
|---|---|---|---|---|---|---|---|
| vector_rag-dev | 0.9s | 2.4s | 1138/63 | $0.00021 | 4.0% | 0 | 0 |
| text2cypher-dev | 1.5s | 2.8s | 1772/224 | $0.00040 | 0.0% | 0 | 0 |

Questions compared / answered validly per run: vector_rag-dev: 109 of 109, text2cypher-dev: 109 of 109.
