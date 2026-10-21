# Agent checks on other models (development evidence, not the benchmark)

Purpose: confirm the agent is not tuned to one model's quirks, using models that are free to run. These are
small samples chosen for debugging, not the evaluation: the official numbers come from the dev/test runs in
Phases 4 and 7 on `gpt-oss-120b`.

| Model (provider) | Set | Result | Tokens per question |
|---|---|---|---|
| `gpt-oss-20b` (Groq) | 10 sanity questions | 10 / 10 | about 2,100 |
| `minimax/minimax-m3.1-flash:free` (OpenRouter) | 10 sanity questions | 9 / 10, then 10 / 10 after one fix | about 2,300 |
| `gpt-oss-20b` (Groq) | 23 mixed dev questions | 91.3 % (optimistic: 4 questions motivated the repair rules) | about 2,500 |
| `minimax/minimax-m3.1-flash:free` (OpenRouter) | 6 dev questions that stress the planner | 5 / 6 (the miss is a fuzzy, judgement-gold question) | about 2,800 |

What the second model found: on the first pass, "KEV CVEs with the weakness CWE-89" failed because the plan
repair kept the cheap `get_neighbors` template for a one-hop route, and `get_neighbors` cannot filter on KEV.
A KEV restriction now always uses `find_paths(kev_only=True)` (regression tests added).

OpenRouter free tier, as observed: 50 requests per day below $10 of purchased credits and 20 per minute. The
whole check above used 40 requests (the client's counter stops at 45). The agent needs about 2.6 requests per
question, so a free account allows roughly 15 to 17 questions a day: enough for debugging, far too little for a
benchmark run. MiniMax answered every request in this session; the other two models probed earlier returned a
provider 404 and an upstream 429, so the client keeps them only as fallbacks.
