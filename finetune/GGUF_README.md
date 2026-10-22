---
base_model: Qwen/Qwen3-1.7B
license: apache-2.0
tags: [gguf, cyber-threat-intelligence, information-extraction, qlora]
---
# RedString-CTI extractor (Qwen3-1.7B, v2, GGUF Q8_0 and Q4_K_M)

The v2 LoRA adapter (`abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2`) merged into Qwen3-1.7B and quantised: `redstring-extractor-q8_0.gguf` (1.7 GB, recommended) and `redstring-extractor-q4_k_m.gguf` (1.0 GB, about 0.09 lower technique F1).
It reads a threat-report chunk and replies with minified JSON: entities (text, type), MITRE ATT&CK technique ids, and
(for sentence-style input) relations. Prompt format: Qwen3 chat with an EMPTY think block. See the project for the exact system prompts.

Trained on ATT&CK procedure sentences (MITRE) and AnnoCTR (CC BY-SA 4.0, Bosch Research). Evaluation numbers belong to the 16-bit
build; the quantised build's scores are reported separately in the project. Outputs are automatic extractions and unverified.

Use it with the project's `make model-fetch` (registers it with Ollama), or directly: the prompt must be sent RAW in the exact
training format (Qwen3 chat markers and an empty think block), see `training_prompt` in the project; Ollama's own chat
template makes the model think aloud.

Licence: Apache-2.0 for the weights (as the base model). The training data includes AnnoCTR (CC BY-SA 4.0, Bosch Research,
https://github.com/boschresearch/anno-ctr-lrec-coling-2024) and MITRE ATT&CK procedure text; please check those terms if you redistribute.
