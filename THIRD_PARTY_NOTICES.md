# Third-party data, models and software

This project's code is the author's own. It builds on, downloads or links to the following; follow each one's terms.

| What | Used for | Terms |
|---|---|---|
| MITRE ATT&CK (v20) | knowledge graph, extractor training text | (c) The MITRE Corporation. ATT&CK is reproduced under MITRE's terms of use: https://attack.mitre.org/resources/terms-of-use/ |
| MITRE CAPEC and CWE | knowledge graph | The MITRE Corporation terms of use: https://capec.mitre.org/about/termsofuse.html , https://cwe.mitre.org/about/termsofuse.html |
| NVD (NIST) | CVE records | US government work; see https://nvd.nist.gov/general/FAQ-Sections/General-FAQs |
| CISA Known Exploited Vulnerabilities catalogue | KEV flags | Published by CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| CISA advisories (aa23-061a, aa23-075a, aa23-136a) | three ingested example reports | Public CISA publications |
| AnnoCTR (Lange et al., LREC-COLING 2024, Bosch Research) | fine-tuning data and the real-report test set | CC BY-SA 4.0: https://github.com/boschresearch/anno-ctr-lrec-coling-2024 . Models trained on it may be subject to the ShareAlike terms: check before redistributing. |
| Qwen3-1.7B (Alibaba) | base model of the extractor | Apache-2.0 |
| BAAI/bge-small-en-v1.5 | embeddings | MIT |
| Neo4j Community Edition | graph database, run in Docker (not redistributed) | GPLv3 |
| llama.cpp | GGUF conversion and quantisation (run in Docker) | MIT |
| Groq API, OpenRouter | agent language model (optional, user's own key) | Their terms of service |

The project itself has no licence file yet: choose one before publishing.
