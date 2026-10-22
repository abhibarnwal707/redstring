# RedString-CTI

Agentic GraphRAG for cyber threat intelligence. A knowledge graph built from MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV;
a LangGraph agent that reaches it only through a read-only MCP server and cites graph IDs; and a QLoRA-fine-tuned
Qwen3-1.7B that turns threat reports into entities, ATT&CK techniques and relations, and links them into the graph.

**Status (2026-10-22).** Graph, evaluation set, retrieval baselines, MCP server, agent, extractor (dataset, training, evaluation,
quantisation) and report ingestion are done. The agent's evaluation on the 109 development questions is **not finished** (it
needs a day of the free Groq token allowance) and the held-out test run has not been made, so no agent accuracy is claimed here yet.

## Quickstart (run it on your own computer)

Nothing needs to be trained or built: the graph and our fine-tuned model are downloaded ready-made (about 2.5 GB in total).

**You need:** [Docker Desktop](https://docs.docker.com/get-docker/) (it runs Neo4j for you, nothing else to install for the database),
[uv](https://docs.astral.sh/uv/getting-started/installation/), [Ollama](https://ollama.com/download) (runs our extractor model), git,
about **8 GB RAM minimum (16 GB recommended)** and **15 GB free disk**. No GPU is needed. Details and what was tested: [docs/local_setup.md](docs/local_setup.md).

```bash
git clone https://github.com/abhibarnwal707/redstring.git && cd redstring
uv sync                 # Python dependencies (installs Python 3.12 if needed)
make doctor             # checks your machine and tells you what is missing
make quickstart         # starts Neo4j, restores the graph, downloads the model, runs a smoke test (5-10 minutes)
make app                # open http://localhost:7860
```

Two tabs need different things: **Extract** (paste a threat report, get entities, ATT&CK techniques and graph links) works with just the
steps above. **Ask** (questions answered from the graph, with citations) also needs a free [Groq API key](https://console.groq.com/keys):
put `GROQ_API_KEY=...` in the `.env` file that `make quickstart` creates, then restart the app.

## Results so far

### Retrieval baselines (109 dev questions, gpt-oss-120b, same scorer; `evals/results/baselines.md`)

| Question type | Vector RAG | Text2Cypher |
|---|---|---|
| single-hop (27) | 11.1% | 96.3% |
| multi-hop (44) | 0% | 70-100% by depth |
| aggregation (18) | 0% | 100% |
| semantic (12) | 33.3% | 16.7% |
| unanswerable (8) | 100% | 75% |
| **overall (109)** | **13.8%** | **79.8%** |

Vector RAG sees node text only, no edges, so relationship questions are impossible for it by construction: this measures what
the graph adds, not that retrieval-augmented generation is weak. The gold answers are computed from the graph, so the benchmark
measures retrieval over this graph. Where Text2Cypher fails (it writes entity IDs from memory) is analysed in
`evals/results/error_analysis_text2cypher.md`.

### Threat-report extractor (`evals/results/extractor_comparison.md`, `extractor_verdict.md`)

Real-report test (78 chunks, expert-annotated AnnoCTR, labels converted automatically; 50 chunks reviewed by hand):

| System | Valid JSON | Entity F1 | ATT&CK technique F1 | Made-up ids |
|---|---|---|---|---|
| Qwen3-1.7B base, 3-shot | 94.9% | 0.352 | 0.226 | 9.2% |
| Fine-tuned v1 (2 epochs) | 97.4% | 0.516 | 0.222 | 3.7% |
| gpt-oss-120b API, zero-shot | 100% | 0.316 | 0.448 | 4.8% |
| **Fine-tuned v2 + schema-constrained decoding** | **100%** | **0.605** | **0.597** | **0%** |
| Same model as the Q8_0 file you download | 100% | 0.585 | 0.583 | 0% |

Honest reading: the v1 run was not worth it; the longer v2 run was. 60% of the real-report technique ids are written in the text
(MITRE tables); recall is 72% on those but only 21% on ids that must be inferred from behaviour (the API model: 3%). The test
set is small (78 chunks) and differences of a few points are noise. Quantising to Q8_0 costs about 0.025 technique F1 and Q4_K_M
about 0.09 (`extractor_quantization.md`).

## Architecture

```
threat report  ->  chunk -> extractor (GGUF) -> validate -> link to graph -> :Report / :ProvisionalEntity (never overwrites curated data)
question       ->  plan -> resolve entities -> retrieve (graph | vector | live CVE | reports) -> answer -> self-check
                                                   |
                                     read-only MCP server (8 tools)  ->  Neo4j
```

- **Graph:** 397,191 nodes, 381,303 edges (ATT&CK v20, CWE 4.20, CAPEC 3.9, NVD, CISA KEV) in Neo4j 5; `BAAI/bge-small-en-v1.5`
  vectors (109,455) in two vector indexes plus a full-text index. Coverage and gaps: `evals/results/data_quality.md`.
- **Extractor:** adapter on the Hugging Face Hub (`abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2`); trained on ATT&CK
  procedure sentences (MITRE) and AnnoCTR (CC BY-SA 4.0, Bosch Research). See `evals/results/finetune_dataset.md`.
- **Report ingestion:** curated nodes are only matched, never modified; entities the graph does not know become provisional;
  report claims use a separate `ASSERTED` relationship so a query cannot mistake a report's claim for ATT&CK's.

## MCP server

`make serve` runs a [FastMCP](https://gofastmcp.com) server over stdio with eight **read-only** tools over the knowledge graph:

| Tool | Use it for |
|---|---|
| `resolve_entity` | name or alias → ID ("Cozy Bear" → G0016); uses the full-text index |
| `semantic_search` | descriptive questions; searches concepts by default, CVEs with `labels=["CVE"]` |
| `get_entity` | properties of one node and its relationship counts |
| `get_neighbors` | direct links, with the ATT&CK procedure text as `evidence` on `USES` edges |
| `find_paths` | multi-hop routes (e.g. Group → Technique → CAPEC → CWE → CVE), `kev_only` for exploited CVEs |
| `cypher_query` | anything else; read-only, 200 rows, 5 seconds |
| `cve_lookup` | graph first, then a cached live NVD lookup (never written to the graph) |
| `report_insights` | what ingested threat reports say against curated ATT&CK: techniques ATT&CK already records vs new ones |

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

## The agent

`redstring_cti.agent.Agent` answers a question in at most a few model calls, and reaches the graph only through the MCP server above:

1. **Plan** (one model call): route (`graph`, `vector`, `hybrid`, `cve_live`, `unanswerable`), query pattern, entity names, target type.
   Questions about ingested reports are routed by a fixed rule, with no model call.
2. **Resolve** names to IDs with the full-text index (no model), then **repair the plan deterministically**: templates first, free-form Cypher only for filters, counts, rankings and intersections.
3. **Retrieve** with the matching tools; evidence records exactly which IDs the answering model was shown.
4. **Answer** (one model call) with inline citations and a machine-readable `FINAL:` line.
5. **Self-check**: every cited ID must be in the evidence, otherwise one revision; an ID that survives is removed and a caveat is added. Budgets (8 tool calls, a token budget, a time limit) are enforced in code.

## Everyday commands

| Task | Command |
|---|---|
| Check the machine / set everything up | `make doctor` / `make quickstart` |
| Start Neo4j / stop it | `make up` / `make down` |
| Run the demo app | `make app` |
| Ingest a real report into the graph | `make ingest-report URL=https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-061a ARGS="--extractor ollama"` (add `--dry-run` to preview; `--drop` removes it) |
| Rebuild the graph from the public sources instead of downloading it | `make download && make load && make embed` (about an hour; needs ~15 GB) |
| Evaluate (research use) | `make eval-vector`, `make eval-t2c`, `make eval-agent` (resumable; the Groq free tier has a daily token cap), `make eval-extractor SPLIT=val` |
| Rebuild the model files | `make finetune-data`, `make ollama-model` (training itself ran on Kaggle: `finetune/notebooks/`) |
| Tests | `make test` (database tests skip when Neo4j is not running) |

## Demo recording

`docs/demo_script.md` has a three-minute walk-through with questions that are known to work.

## Hosted deployment

A hosted demo was prepared (`deploy/`, `docs/deployment.md`: one container with Neo4j, the quantised model and the app) and tested
locally, but Hugging Face no longer offers free Docker Spaces, so the supported way to run the project is locally, as above.

## Limitations

- The agent has not been evaluated end to end yet (see Status); the Ask tab of the demo has not been tried against live Groq.
- The gold set is generated from the graph (it measures retrieval, not whether the graph is complete); semantic questions have fuzzy judgements.
- Paths from a technique to a CVE through CAPEC and CWE mean "shares a weakness", not "was exploited"; only 25% of ATT&CK techniques have a CAPEC link.
- Extractor labels for real reports are an expert annotation converted automatically; only part of the test set was reviewed by hand.
- Report extractions are unverified; noise such as an organisation typed as a threat actor still reaches the provisional layer.
- Free-tier API limits shape the evaluation: runs use one model, are resumable, and the held-out test split is run once, last.

## Repository map

`src/redstring_cti/` ingest, graph, gold, retrieval, mcp_server, agent, extractor, app; `evals/` runners, gold set and results;
`finetune/` Kaggle notebook and model build scripts; `deploy/` Space container; `docs/deployment.md`; `tests/`.
