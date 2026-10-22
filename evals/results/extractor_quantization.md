# Quantisation of the v2 extractor (validation, 197 rows)

Served by Ollama on an Apple GPU from the merged model. Same rows and scorer as `extractor_comparison.md`.
Latency is per chunk on this Mac and says nothing about CPU speed on a Hugging Face Space.

| Build | File size | Valid JSON | Entity F1 | Technique F1 | Relation F1 | Made-up ids | Median latency |
|---|---|---|---|---|---|---|---|
| 16-bit, HF adapter on base (reference) | adapter only | 100% | 0.823 | 0.578 | 0.600 | 0.6% | |
| 16-bit merged (Ollama) | 3.4 GB | 99.5% | 0.827 | 0.578 | 0.600 | 0.6% | 1.7 s |
| Q8_0 | 1.7 GB | 99.5% | 0.826 | 0.553 | 0.580 | 0.6% | 1.3 s |
| Q8_0 + schema-constrained | 1.7 GB | 100% | 0.824 | 0.551 | 0.580 | 0% | 1.2 s |
| Q4_K_M | 1.0 GB | 97.5% | 0.814 | 0.482 | 0.508 | 0.6% | 0.9 s |
| Q4_K_M + schema-constrained | 1.0 GB | 99.5% | 0.810 | 0.487 | 0.508 | 0% | 1.0 s |

Findings
- The merged 16-bit model reproduces the adapter-on-base numbers exactly (technique F1 0.578): the merge and GGUF conversion are correct.
- Q4_K_M costs about 0.09 technique F1 and 0.09 relation F1; Q8_0 costs about 0.025. The Space uses Q8_0 with schema-constrained output.
- Constraining fixes format (valid JSON, no made-up ids) at every size and does not change accuracy.
- Test-set scores were measured on the 16-bit build; the Q8_0 test scores have not been run.
