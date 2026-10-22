---
title: RedString-CTI
emoji: 🧵
colorFrom: red
colorTo: gray
sdk: docker
app_port: 7860
pinned: false
---

# RedString-CTI

Agentic GraphRAG over MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV, with a fine-tuned 1.7B threat-report extractor.
Space secrets needed: `NEO4J_PASSWORD`, `HF_TOKEN`, `GROQ_API_KEY`. Optional: `REDSTRING_EXTRACTOR` (`llama:<gguf path>`), `REDSTRING_RATE_LIMIT`, `REDSTRING_MAX_CHUNKS`.
