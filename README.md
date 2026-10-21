# RedString-CTI

Agentic GraphRAG for cyber threat intelligence over MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV, with a QLoRA-fine-tuned threat-report extractor.

**Status:** Phases 0–3 complete (data download, knowledge graph, embeddings, data-quality report, 150-question gold evaluation set). Phase 4 (retrieval baselines) is built; the Text2Cypher dev run resumes with `make eval-t2c` (interim results in `evals/results/baselines.md`). Phase 5 (MCP server) is complete. Next: the LangGraph agent. Build guide: the execution playbook (see the checklist in it).

| What | Where |
|---|---|
| Graph: 397,191 nodes, 381,303 edges (ATT&CK v20, CWE 4.20, CAPEC 3.9, NVD, CISA KEV) | `make download && make up && make load` |
| Embeddings (`BAAI/bge-small-en-v1.5`, 109,455 vectors) | `make embed` |
| Data-quality and coverage report | `evals/results/data_quality.md` (`make dq`) |
| Why this embedding model | `evals/results/embedding_model_choice.md` |
| Gold evaluation set (150 questions, answers computed from the graph) | `evals/gold/` (`make gold`) |
| Tests | `make test` |

## MCP server

`make serve` runs a [FastMCP](https://gofastmcp.com) server over stdio with seven **read-only** tools over the knowledge graph:

| Tool | Use it for |
|---|---|
| `resolve_entity` | name or alias → ID ("Cozy Bear" → G0016); uses the full-text index |
| `semantic_search` | descriptive questions; searches concepts by default, CVEs with `labels=["CVE"]` |
| `get_entity` | properties of one node and its relationship counts |
| `get_neighbors` | direct links, with the ATT&CK procedure text as `evidence` on `USES` edges |
| `find_paths` | multi-hop routes (e.g. Group → Technique → CAPEC → CWE → CVE), `kev_only` for exploited CVEs |
| `cypher_query` | anything else; read-only, 200 rows, 5 seconds |
| `cve_lookup` | graph first, then a cached live NVD lookup (never written to the graph) |

Use it from Claude (Neo4j must be running: `make up`):

```bash
# Claude Code
claude mcp add redstring -- uv --directory /path/to/redstring run python -m redstring_cti.mcp_server.server
```
```json
// Claude Desktop: claude_desktop_config.json (use the absolute path to uv: the app does not inherit your shell PATH)
{"mcpServers": {"redstring": {"command": "/path/to/uv",
  "args": ["--directory", "/path/to/redstring", "run", "python", "-m", "redstring_cti.mcp_server.server"]}}}
```

**Security model.** Neo4j Community has no role-based access control, so read-only access is enforced in
layers, and the first two are the enforcement: (1) every query runs in a *read* transaction, where the
server itself refuses writes; (2) a deny-list rejects writes, admin and `apoc` calls, multiple statements and
unbounded paths before anything is sent, and only two index procedures are allowed. A 5-second transaction
timeout and a 200-row cap bound the cost. Every call is appended to `data/processed/audit.jsonl`.

Paths from a group or technique to a CVE go through CAPEC and CWE and mean "shares a weakness", not "the
group exploited this CVE"; the tools say so in their output.
