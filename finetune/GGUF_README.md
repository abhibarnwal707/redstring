---
base_model: Qwen/Qwen3-1.7B
license: apache-2.0
tags: [gguf, cyber-threat-intelligence, information-extraction, qlora]
---
# RedString-CTI extractor (Qwen3-1.7B, v2, Q4_K_M)

The v2 LoRA adapter (`abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2`) merged into Qwen3-1.7B and quantised to Q4_K_M.
It reads a threat-report chunk and replies with minified JSON: entities (text, type), MITRE ATT&CK technique ids, and
(for sentence-style input) relations. Prompt format: Qwen3 chat with an EMPTY think block. See the project for the exact system prompts.

Trained on ATT&CK procedure sentences (MITRE) and AnnoCTR (CC BY-SA 4.0, Bosch Research). Evaluation numbers belong to the 16-bit
build; the quantised build's scores are reported separately in the project. Outputs are automatic extractions and unverified.
