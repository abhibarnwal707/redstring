# RedString-CTI

Agentic GraphRAG for cyber threat intelligence. A knowledge graph built from MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV lives in Neo4j. A LangGraph agent routes each question to graph, vector, hybrid or live-CVE retrieval through a FastMCP server and cites the graph paths it used. A QLoRA-fine-tuned Qwen3-1.7B extracts entities, techniques and relations from threat reports. The full build guide is `../redstring-playbook.md`.

## Conventions
- Python 3.12, package `redstring_cti` (never name it `redstring`: it clashes with a PyPI library).
- Type hints everywhere; Pydantic models for every record.
- `ruff` and `mypy` must pass.
- Every ingester is idempotent: `MERGE`, never `CREATE`.
- Raw data stays in `data/raw` and is never committed.

## Commands
- `make download`, `make load`, `make test`, `make eval`, `make lint`
- `make up` / `make down` for Neo4j

## Rules
- Never write to Neo4j from MCP tools.
- Never hard-code secrets; use `.env`.
- Commit messages include metrics where relevant.

## Current phase
Phase 0 — project setup
