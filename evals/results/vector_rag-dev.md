# vector_rag on the dev split

- System: `vector_rag`; split: `dev`; 109 questions scored.
- Correct = ID F1 >= 0.8 (lists), exact number (counts), says not found (unanswerable). Ranked lists are scored as sets; order is reported in the per-question CSV.
- The 11 questions used as Text2Cypher few-shot examples are excluded for every system so tables are comparable.

| Question group | n | Accuracy (F1>=0.8 / exact) | Mean F1 | Cited IDs not in evidence |
|---|---|---|---|---|
| aggregation (count) | 9 | 0.0% | n/a | n/a |
| aggregation (ranked) | 9 | 0.0% | 0.0% | 100.0% |
| multi_hop (2-hop) | 28 | 0.0% | 1.4% | 0.0% |
| multi_hop (3-hop) | 13 | 0.0% | 0.0% | 0.0% |
| multi_hop (4-hop) | 3 | 0.0% | 0.0% | n/a |
| semantic | 12 | 33.3% | 49.0% | 0.0% |
| single_hop | 27 | 11.1% | 18.0% | 0.0% |
| unanswerable | 8 | 100.0% | n/a | n/a |
| **overall** | 109 | 13.8% | 12.1% | 4.0% |

Service time per question: p50 0.9s, p95 2.4s (retrieval and model calls, without rate-limit waits); wall clock p50 7.5s, p95 10.8s because the free tier allows only 8,000 tokens per minute. Tokens per question: 1138 in / 63 out. Reference cost: $0.00021 per question (Groq list prices; the free tier costs nothing). Query/answer errors: 0. Questions that fell back to another model: 0. Models used: openai/gpt-oss-120b.
