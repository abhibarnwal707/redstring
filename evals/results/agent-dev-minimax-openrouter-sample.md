# agent on the dev split

- System: `agent`; split: `dev`; 6 questions scored.
- Correct = ID F1 >= 0.8 (lists), exact number (counts), says not found (unanswerable). Ranked lists are scored as sets; order is reported in the per-question CSV.
- The 11 questions used as Text2Cypher few-shot examples are excluded for every system so tables are comparable.

| Question group | n | Accuracy (F1>=0.8 / exact) | Mean F1 | Cited IDs not in evidence |
|---|---|---|---|---|
| multi_hop (2-hop) | 2 | 100.0% | 100.0% | 0.0% |
| multi_hop (4-hop) | 1 | 100.0% | 100.0% | 0.0% |
| semantic | 1 | 0.0% | 50.0% | 0.0% |
| single_hop | 1 | 100.0% | 100.0% | 0.0% |
| unanswerable | 1 | 100.0% | n/a | n/a |
| **overall** | 6 | 83.3% | 90.0% | 0.0% |

Service time per question: p50 5.7s, p95 12.9s (retrieval and model calls, without rate-limit waits); wall clock p50 7.7s, p95 14.7s because the free tier allows only 8,000 tokens per minute. Tokens per question: 2328 in / 267 out. Reference cost: $0.00000 per question (Groq list prices; the free tier costs nothing). Query/answer errors: 0. Questions that fell back to another model: 0. Models used: openrouter:minimax/minimax-m3.1-flash:free.

Agent: routes {'graph': 3, 'hybrid': 1, 'unanswerable': 1, 'vector': 1}; 2.5 tool calls and 2.3 model calls per question; self-check verdicts {'pass': 6}; 0 questions hit a budget.
