# How RedString-CTI is deployed

Ollama runs on one laptop, so it is only the local-development path. The public demo has no GPU and no laptop behind it.

| Part | Local development | Public demo (Hugging Face Space, free CPU) |
|---|---|---|
| UI | `make serve` / Gradio on localhost | Gradio in the Space |
| Agent LLM | Groq (or OpenRouter) via API key in `.env` | Groq, key in Space Secrets, per-session rate limit |
| Extractor | HF adapter on the Mac GPU, or Ollama (GGUF) | the same v2 model as a quantised GGUF, CPU, `LlamaCppExtractor` with a JSON-schema grammar |
| Graph | Neo4j in Docker (397K nodes) | a SUBSET graph (see below) on a hosted Neo4j |
| Model files | Hugging Face Hub | GGUF in a Hub model repo, downloaded at Space start |

## Extractor on CPU
- Source: adapter `abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2` merged into `Qwen/Qwen3-1.7B`, converted to GGUF and quantised to Q8_0 (1.7 GB), the size chosen from `evals/results/extractor_quantization.md` (Q8_0 loses about 0.025 technique F1 against 16-bit, Q4_K_M about 0.09).
- Runtime: `llama-cpp-python` (prebuilt CPU wheels exist for Linux; it does not build on every dev machine, so it is imported lazily and installed on the Space only).
- Speed, measured in the Space image limited to 2 CPUs on this Mac (native arm64, so a rough proxy; a Space's x86 CPUs may be slower): model load 0.8 s, a two-sentence report 21 s, a full 1,400-character chunk 44 s. The demo therefore processes at most 2 chunks (`REDSTRING_MAX_CHUNKS=2`) and says so.
- Quantisation changes accuracy: measured on validation, see `extractor_quantization.md`. Test-set numbers were measured on the 16-bit build only.

## Graph in the demo
Neo4j runs INSIDE the Space container (Neo4j and the JDK are copied from the official image), loaded at start from a subset dump hosted in a private Hugging Face dataset repo (`abhibarnwal707/redstring-cti-graph-subset`, 689 MB), so no hosted-database limit applies. The subset (109,515 nodes, 154,535 relationships): every ATT&CK, CAPEC and CWE node (3,344), the KEV CVEs (1,754) and the CVEs on the Technique-CAPEC-CWE chain (about 105K), about 108K nodes. Checked: all 150 gold questions have identical answers on the subset (the gold tests pass against it). The subset keeps the three ingested CISA reports. The dump is rebuilt with `finetune/export_subset.py` because `neo4j-admin database copy` is Enterprise-only and a plain dump of a pruned database is padded with the space left by deleted records.

## Secrets and limits
No secret is stored in the image or the repo: `NEO4J_*`, `GROQ_API_KEY` and `HF_TOKEN` come from the environment. The Space applies a per-session request cap so one visitor cannot exhaust the Groq free-tier daily token cap (about 285K tokens a day on the primary model, shared with everything else using that key).

## Image
`Dockerfile` builds the runtime image (3.3 GB with the full dependency set; the training and evaluation dependencies could be split into an optional group to slim it before the Space build).

## Build and boot (verified locally, not yet on a Space)
`python deploy/build_space_bundle.py` assembles `build/space/` (Dockerfile, entrypoint, README with the Space front matter, source, benchmark tables). `docker build` of that folder gives a 4.6 GB image. Booting it downloads the graph dump (and the Q8_0 GGUF), loads it into Neo4j, starts Neo4j and the app: ready after about 130 s on this Mac, 1.2 GB resident before the extractor runs. Secrets (`NEO4J_PASSWORD`, `HF_TOKEN`, `GROQ_API_KEY`) are environment variables, never in the image. Not verified: Hugging Face's own limits for image size and start time, and the Ask tab against live Groq.
