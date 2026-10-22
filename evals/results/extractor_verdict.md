# When fine-tuning was and wasn't worth it

Numbers are from `extractor_comparison.md`. The system was chosen on the VALIDATION set (v2 over v1); the test sets
were then run once for every system. Test sets: 78 real-report chunks (AnnoCTR) and a fixed sample of 100 ATT&CK sentences.

| What | Verdict | Evidence (real-report test) |
|---|---|---|
| Valid JSON | Fine-tuning won | base 3-shot 94.9%, fine-tuned v2 97.4%, with schema-constrained decoding 100%; base zero-shot 23% |
| Made-up ATT&CK ids | Fine-tuning plus constrained decoding won | base 3-shot 9.2%, v2 2.6%, v2 constrained 0% (API model 4.8%) |
| Entity extraction | Fine-tuning won | entity F1 0.605 (v2 constrained) vs 0.316 (120B API, zero-shot) vs 0.352 (base 3-shot) |
| Technique ids | Fine-tuning won, after a second, longer run | F1 0.597 (v2 constrained) vs 0.448 (API) vs 0.222 (v1). v1 (2 epochs, 10 examples per technique) was NOT worth it here |
| Relations | Fine-tuning won on sentences | 0.490 vs 0.000 (API); AnnoCTR has no relation labels |
| Cost and speed | Local won | about 3 s per chunk on a laptop GPU, no per-call cost; the API cost about $0.19 per 1,000 chunks and 1.2 s |
| Reasoning about techniques NOT written in the text | Still weak | recall 6 of 29 (v2) vs 1 of 29 (API) |

## Caveats that change how to read the table
- 60% of the real-report technique ids (43 of 72) are written verbatim in the chunk (MITRE technique tables). Copying them
  accounts for most of the score: recall 72% on those, but only 21% on ids that must be inferred from behaviour. The API model
  copies about as well (67%) but almost never infers (3%).
- The test sets are small (78 chunks, 30 of them with any technique), so differences of a few points are noise.
- AnnoCTR technique labels are an expert annotation converted automatically; 50 of the test chunks were reviewed by hand.
  The training labels have no such review.
- Procedure-sentence gains are not leakage: only 1% of test sentences are within 0.8 token overlap of a training sentence
  (median best overlap 0.32), and train and test never share a source object.
- Evaluation ran on the 16-bit base plus the adapter on a Mac; the adapter was trained on the 4-bit base.
- The zero-shot API baseline was not prompt-tuned; a few-shot or schema-aware prompt would likely narrow the entity gap.
