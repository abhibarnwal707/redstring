# Embedding model choice

Reproduce: `uv run python evals/runners/compare_embedders.py --out evals/results/embedding_model_choice.table.md`
(about 3 minutes on an Apple-silicon Mac using MPS; reads text from the live graph).

## Tasks (all built from the real graph, nothing hand-labelled except C)

| Task | Query | Candidates | n |
|---|---|---|---|
| A | an ATT&CK procedure sentence (a real `USES` description) | 706 techniques | 400 |
| B | a CVE description | 944 CWEs; gold = the CVE's Primary CWE | 400 |
| C | a hand-written analyst question | all 3,344 non-CVE nodes | 20 |
| D | an alias such as "Cozy Bear" | Group + Software nodes; gold = the owner | 200 |

Metrics: R@k = share of queries whose gold item is in the top k; MRR = mean reciprocal rank. Documents are
`"{label}: {name} (also known as: ...). {description[:1000]}"`, max 256 tokens. Seed 42.

## Results

| Model | dim | A R@1 | A R@5 | A MRR | B R@5 | B R@10 | B MRR | C R@1 | C R@5 | D R@1 | D R@5 | docs/s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| bge-small-en-v1.5 | 384 | 0.350 | 0.573 | 0.456 | 0.270 | 0.335 | 0.214 | 0.60 | 0.85 | 0.390 | 0.570 | 363 |
| bge-small-en-v1.5 [no aliases] | 384 | 0.350 | 0.573 | 0.456 | 0.270 | 0.335 | 0.214 | 0.60 | 0.85 | 0.115 | 0.145 | 366 |
| bge-small-en-v1.5 [no query prefix] | 384 | 0.330 | 0.537 | 0.431 | 0.212 | 0.273 | 0.171 | 0.60 | 0.85 | 0.385 | 0.565 | 355 |
| all-MiniLM-L6-v2 | 384 | 0.300 | 0.552 | 0.424 | 0.240 | 0.343 | 0.165 | 0.40 | 0.80 | 0.305 | 0.470 | 672 |
| gte-small | 384 | 0.340 | 0.557 | 0.438 | 0.223 | 0.290 | 0.177 | 0.70 | 0.90 | 0.395 | 0.660 | 940 |
| e5-small-v2 | 384 | 0.318 | 0.532 | 0.425 | 0.228 | 0.290 | 0.189 | 0.65 | 0.85 | 0.395 | 0.610 | 344 |
| bge-base-en-v1.5 | 768 | 0.312 | 0.585 | 0.440 | 0.282 | 0.403 | 0.216 | 0.60 | 0.85 | 0.385 | 0.590 | 101 |

`[no aliases]` leaves the aliases out of the document text. `[no query prefix]` omits the BGE retrieval
instruction on queries. Standard error is about +/-0.025 for A and B, +/-0.035 for D, and much larger for C
(n=20, so two questions are 0.10).

## What the evidence says

1. **No small model dominates.** `bge-small` is best or tied on A and B; `gte-small` is slightly better on C and
   D and 2.6x faster. Most gaps are within noise. Absolute scores are modest (A R@5 about 0.57, B R@5 about 0.27)
   because these tasks are hard and the labels are ambiguous (a CVE fits several related CWEs), which is why
   retrieval is hybrid (graph + full-text + vectors) rather than vectors alone.
2. **Aliases in the document text matter a lot for alias queries**: D R@1 0.390 with aliases vs 0.115 without.
3. **The BGE query prefix matters** for A and B (B R@5 0.270 vs 0.212) and is neutral on D. It is applied to
   queries only, never to documents.
4. **`bge-base` is not worth it**: better only on B R@10, 3.5x slower, and 768 dims double storage and index size.
5. **Even with aliases, a bare name is not reliably found by vector search** (D R@1 0.39). Name and alias lookup is
   the full-text index's job (`text_search` indexes `aliases`); vectors are for descriptive queries.

**Decision: `BAAI/bge-small-en-v1.5`, 384-d, query prefix on, aliases in the text.**

Caveat: a first run of this table compared `bge-small` with and without aliases but also changed the prefix, which
confounded the two; the table above is the controlled rerun.

## Index layout (found while testing the build)

A single vector index over all nodes let 106K CVEs crowd out the 3.3K concept nodes: a search for "Cozy Bear"
returned four unrelated CVEs and "SQL injection" ranked a CVE above CWE-89. The graph therefore has two vector
indexes, `ref_vec` (every non-CVE node, label `:Reference`) and `cve_vec` (`:CVE`), plus the `text_search`
full-text index. CVE vectors cover KEV CVEs and CVEs reachable through the Technique-CAPEC-CWE chain
(106,111 of 393,847); the rest are found via full-text search or by ID.
