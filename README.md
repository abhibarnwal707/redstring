# RedString-CTI

Agentic GraphRAG for cyber threat intelligence over MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV, with a QLoRA-fine-tuned threat-report extractor.

**Status:** Phases 0–2 complete (data download, knowledge graph, embeddings, data-quality report). Next: the gold evaluation set. Build guide: the execution playbook (see the checklist in it).

| What | Where |
|---|---|
| Graph: 397,191 nodes, 381,303 edges (ATT&CK v20, CWE 4.20, CAPEC 3.9, NVD, CISA KEV) | `make download && make up && make load` |
| Embeddings (`BAAI/bge-small-en-v1.5`, 109,455 vectors) | `make embed` |
| Data-quality and coverage report | `evals/results/data_quality.md` (`make dq`) |
| Why this embedding model | `evals/results/embedding_model_choice.md` |
| Tests | `make test` |
