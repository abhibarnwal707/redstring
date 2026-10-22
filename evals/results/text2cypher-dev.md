# text2cypher on the dev split

- System: `text2cypher`; split: `dev`; 109 questions scored.
- Correct = ID F1 >= 0.8 (lists), exact number (counts), says not found (unanswerable). Ranked lists are scored as sets; order is reported in the per-question CSV.
- The 11 questions used as Text2Cypher few-shot examples are excluded for every system so tables are comparable.

| Question group | n | Accuracy (F1>=0.8 / exact) | Mean F1 | Cited IDs not in evidence |
|---|---|---|---|---|
| aggregation (count) | 9 | 100.0% | n/a | 0.0% |
| aggregation (ranked) | 9 | 100.0% | 100.0% | 0.0% |
| multi_hop (2-hop) | 28 | 71.4% | 74.5% | 0.0% |
| multi_hop (3-hop) | 13 | 92.3% | 92.3% | 0.0% |
| multi_hop (4-hop) | 3 | 100.0% | 100.0% | 0.0% |
| semantic | 12 | 16.7% | 46.2% | 0.0% |
| single_hop | 27 | 96.3% | 96.3% | 0.0% |
| unanswerable | 8 | 75.0% | n/a | n/a |
| **overall** | 109 | 79.8% | 83.1% | 0.0% |

Service time per question: p50 1.5s, p95 2.8s (retrieval and model calls, without rate-limit waits); wall clock p50 4.8s, p95 16.0s because the free tier allows only 8,000 tokens per minute. Tokens per question: 1772 in / 224 out. Reference cost: $0.00040 per question (Groq list prices; the free tier costs nothing). Query/answer errors: 0. Questions that fell back to another model: 0. Models used: openai/gpt-oss-120b.
