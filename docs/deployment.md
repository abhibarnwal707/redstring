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
- Source: adapter `abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2` merged into `Qwen/Qwen3-1.7B`, converted to GGUF, quantised (Q4_K_M, about 1 GB expected).
- Runtime: `llama-cpp-python` (prebuilt CPU wheels exist for Linux; it does not build on every dev machine, so it is imported lazily and installed on the Space only).
- Cost: unmeasured on a Space. A 1,400-character chunk produces about 150 tokens; at the CPU speeds a free Space is expected to give, that is tens of seconds per chunk, so the demo caps how many chunks it processes and says so.
- Quantisation can change accuracy. The evaluation numbers were measured with the 16-bit base plus adapter; the GGUF must be re-scored with `evals/runners/run_extractor_eval.py` before any claim is made about it.

## Graph in the demo
The full graph (397,191 nodes) is probably too large for a free hosted Neo4j (limits to be verified before choosing one). The subset to ship: every ATT&CK, CAPEC and CWE node (3,344), the KEV CVEs (1,754) and the CVEs on the Technique-CAPEC-CWE chain (about 105K), about 108K nodes. The gold questions answer identically on that subset only if they never need the other CVEs: this must be checked with the gold tests before the subset is used for any number.

## Secrets and limits
No secret is stored in the image or the repo: `NEO4J_*`, `GROQ_API_KEY` and `HF_TOKEN` come from the environment. The Space applies a per-session request cap so one visitor cannot exhaust the Groq free-tier daily token cap (about 285K tokens a day on the primary model, shared with everything else using that key).

## Image
`Dockerfile` builds the runtime image (3.3 GB with the full dependency set; the training and evaluation dependencies could be split into an optional group to slim it before the Space build).
