# RedString-CTI — Purpose, Data, Models, and What Each Phase Uses

> **Status (2026-10-21): Phases 0–6 and 8 are done; Phase 7 (evaluation, needs Groq tokens) and Phase 9 (QLoRA training on Kaggle) are next.** Two runs wait for the Groq daily token quota to reset: finishing the Text2Cypher dev evaluation (Phase 4) and re-validating the agent's sanity questions on the primary model (Phase 6). The graph holds 397,191 nodes and 381,303 edges, 109,455 of them embedded. Numbers: `evals/results/data_quality.md`. Embedding-model evidence: `evals/results/embedding_model_choice.md`.

## 1. The one-paragraph version

Security teams drown in information about attackers and software flaws, and that information lives in **separate public databases that don't talk to each other**. RedString-CTI connects those databases into one **knowledge graph**, then lets you ask questions in plain English ("Which weaknesses do APT29's techniques exploit, and which actively-exploited CVEs map to them?"). The answer comes with **citations to the exact graph paths** it was derived from, so nothing has to be taken on trust. A second component, a **small fine-tuned language model**, reads raw threat-report text and turns it into structured facts that can be added to the graph.

It is a portfolio/resume project. It is built on real, current, public security data and uses techniques that are used in industry, but it is not a production security product (see section 8).

---

## 2. The problem it solves

Suppose an analyst wants to know: *"Which techniques does APT29 use, which weaknesses do they exploit, and which CVEs map to them?"*

The answer is spread across four sources:

| Fact | Where it lives |
|---|---|
| APT29 uses technique T1190 | MITRE ATT&CK |
| T1190 relates to attack pattern CAPEC-xxx | MITRE ATT&CK + CAPEC |
| That attack pattern exploits weakness CWE-yyy | CAPEC |
| CVE-zzzz is an instance of weakness CWE-yyy | NVD |

The link is a **chain of joins**:

```
Group ──USES──▶ Technique ◀──MAPS_TO── CAPEC ──EXPLOITS──▶ CWE ◀──HAS_WEAKNESS── CVE
(APT29)         (T1190)               (CAPEC-xx)           (CWE-yy)               (CVE-zzzz)
```

**Plain "vector RAG"** (the usual chatbot-over-documents approach) searches for text that *sounds similar* to the question. It cannot follow that chain, because no single document contains the whole chain. A **graph** can: it stores the links explicitly and walks them. That difference is the core claim the project tests with numbers.

---

## 3. The datasets (what, where from, how big, where stored)

All are public, free, and maintained by well-known organisations.

| Dataset | Maintainer | What it is | Format | Size here | Stage that uses it |
|---|---|---|---|---|---|
| **MITRE ATT&CK Enterprise v20** | MITRE | The standard catalogue of attacker behaviour: threat **groups**, their **techniques** (e.g. T1566 Phishing), **tactics** (the attacker's goal, e.g. Initial Access), **malware/tools**, **mitigations**, and **campaigns**, with relationships between them. Also contains short real-world "procedure examples" of how a group used a technique. | STIX 2.1 JSON | 55 MB | P2 (graph), P3 (questions), P8 (fine-tuning text) |
| **CWE** (Common Weakness Enumeration) | MITRE | A catalogue of *types of software weakness* (e.g. CWE-89 SQL injection) in a hierarchy. | XML in a zip | 2 MB | P2 |
| **CAPEC** (Common Attack Pattern Enumeration) | MITRE | Catalogue of *how attackers exploit weaknesses* (e.g. CAPEC-66 SQL Injection). Links attack patterns to CWEs and to ATT&CK techniques. It is the **bridge** between ATT&CK and CWE. | XML | 4 MB | P2 |
| **NVD** (National Vulnerability Database) | NIST (US) | Every published **CVE** (specific vulnerability in specific software) with description, severity score (CVSS), publication date, and which CWE it is an instance of. Expect 200K+ CVEs. | JSON 2.0, one gzipped file per year (2002 → 2026) plus a "modified" feed | ~400–500 MB compressed; roughly 290 MB uncompressed for 2024 alone | P2 |
| **CISA KEV** (Known Exploited Vulnerabilities) | US CISA | A short list of CVEs **confirmed to be exploited in the wild**. 1,754 entries as of 2026.10.20. Used to mark which CVEs matter most. | JSON | 1.8 MB | P2 (flag `kev=true`), P3 |

**Fine-tuning datasets** (not downloaded yet, Phase 8):

| Dataset | What it gives | Notes |
|---|---|---|
| ATT&CK procedure examples | Sentences like "APT29 used X to do Y" labelled with the technique. Comes from the ATT&CK file we already have. | High-quality labels |
| ~~TRAM-Clean~~ | Not used (a cleaning protocol in a paper, not a download; raw TRAM is noisy) | Skipped |
| AnnoCTR | 120 annotated threat reports (entities + ATT&CK techniques), CC BY-SA 4.0, verified | 853 chunks, the official report split kept |

### Where things are stored

| Stage of the data | Location | Committed to git? |
|---|---|---|
| Raw downloads | `redstring/data/raw/` (+ `MANIFEST.json` with URL, SHA-256, timestamp, version for each file) | No (gitignored) |
| The knowledge graph | Neo4j database in Docker; its files are in `redstring/data/neo4j/` | No |
| Parsed/intermediate data | `redstring/data/processed/` | No |
| Gold question set and result tables | `redstring/evals/gold/`, `redstring/evals/results/` | Yes |
| Fine-tuning data | `redstring/finetune/data/` and a private Kaggle dataset | No |
| Trained adapter / model | Hugging Face Hub (adapter), GGUF file for local use | Not in git |

---

## 4. Does it only work on these datasets?

**No.** Three separate answers:

1. **The pipeline is general.** The graph schema, the loaders, the MCP tools, and the agent don't care what the facts are. The same approach works for any domain with linked reference data. ATT&CK, CAPEC, CWE, NVD and KEV are simply the best real-world example for security.
2. **The data keeps moving, and the project handles it.** NVD publishes new CVEs daily and ATT&CK ships new versions. Phase 13 adds `make update`, which applies the NVD "modified" feed and newer ATT&CK versions and logs what changed.
3. **New knowledge can come in from raw text.** The fine-tuned extractor reads a fresh threat report (a blog post, a vendor PDF), pulls out the actors, malware, CVEs, techniques and relations, and adds them to the graph as clearly marked `provisional` nodes, **never overwriting** the curated MITRE data.

What it will **not** do: it knows nothing about *your* network, logs, or alerts. It is a knowledge system about the public threat landscape, not a detection system.

---

## 5. The models

| Model | Role | Where it runs | Stage |
|---|---|---|---|
| **`BAAI/bge-small-en-v1.5`** (embedding model, 384-dim). **Chosen** over all-MiniLM-L6-v2, gte-small, e5-small-v2 and bge-base by a 4-task test on our own graph | Turns node text (name, aliases, description) into a vector for "similar meaning" search. Queries get the BGE retrieval prefix; documents do not | Locally on the Mac (Apple GPU / MPS), 300–700 docs/s | P2 build vectors, P4–P6 query vectors |
| **Groq-hosted LLM** (free tier; specific model chosen in Phase 4) | The **agent's brain**: routes questions, writes Cypher for the Text2Cypher baseline, writes the final cited answer, and is the LLM-judge for faithfulness checks | Groq cloud API (key in `.env`) | P4, P6, P7, P12 |
| **Qwen3-1.7B (base)** | The model we **fine-tune** | Kaggle free GPU (T4/P100) for training | P9 |
| **Qwen3-1.7B + LoRA adapter** ("the extractor") | Reads threat-report text and outputs structured JSON (entities, techniques, relations) | Training on Kaggle; then merged and quantised to **GGUF Q4_K_M** (about 1 GB) and run on CPU/Mac with Ollama or llama.cpp | P9 train, P10 eval, P11 use, P12 demo |
| **One API model** (reference only) | A strong "ceiling" to compare the small extractor against, and optionally the agent LLM for comparison | API, a small number of calls | P7, P10 |

**Why fine-tune something so small?** The claim being tested is: *a 1.7B model, taught on the right data, gets close to an API model at a fraction of the cost and can run for free on a laptop CPU.*

**QLoRA** = the base model is loaded in 4-bit to save memory, and we train only small "adapter" layers on top. That is what makes fine-tuning possible on a free Kaggle GPU.

**Cost accounting.** Even when something runs for free, the evaluation reports a notional **$/query** using a reference API price list, so cost numbers are comparable.

---

## 6. How the pieces fit together

```
 Raw files (data/raw)
        │  Phase 1: download.py + MANIFEST
        ▼
 Parsers / ingesters (ATT&CK, CWE, CAPEC, NVD, KEV)        Phase 2
        │  MERGE into Neo4j in batches
        ▼
 Neo4j knowledge graph  ◀────────────── embeddings (bge-small): 3,344 concept nodes in `ref_vec`,
        │                                  106,111 CVEs (KEV or on the chain) in `cve_vec`;
        │                                  `text_search` full-text index on names, descriptions, aliases
        │
        │ read-only access only
        ▼
 FastMCP server (7 read-only tools + guardrails + audit log) Phase 5  [DONE]
        │  tools: semantic_search, resolve_entity, get_entity, get_neighbors,
        │         find_paths, cypher_query, cve_lookup
        ▼
 LangGraph agent (Groq LLM, reaches the graph only through MCP)  Phase 6  [DONE]
   plan (route, pattern, entity names) → resolve names to IDs → deterministic plan repair (templates first)
   → retrieve (graph / vector / hybrid / live CVE) → answer with citations
   → self-check (every cited ID must be in the evidence; one revision; then strip)
        │
        ▼
 Gradio UI on a Hugging Face Space                          Phase 12

 Side loop (Phases 8–11):
 Threat report text → fine-tuned Qwen3-1.7B (GGUF) → JSON → validate → link to graph nodes
        → provisional nodes + edges in Neo4j
```

Why MCP (Model Context Protocol) in the middle: the same server can be used by our agent **and** by Claude Desktop/Claude Code, so the graph becomes a reusable tool, not code locked into one app.

---

## 7. Phase by phase: what each stage does, uses, and produces

| Phase | What happens | Data used | Models used | Output |
|---|---|---|---|---|
| **P0 Setup** | Repo, Python env, Neo4j in Docker, config, smoke test | none | none | Working scaffold (done) |
| **P1 Download** | Fetch all raw sources with retries, concurrency, hash-based skip; write manifest | All five sources (over the network) | none | `data/raw/*` + `MANIFEST.json` |
| **P2 Graph** | Parse each source, drop revoked/deprecated/rejected items, create typed nodes and relationships, add KEV flags, compute embeddings, produce a data-quality report and 10 sanity queries. **DONE** | ATT&CK, CWE, CAPEC, NVD, KEV | bge-small (embeddings) | Neo4j graph, `data_quality.md` |
| **P3 Gold set** | Write 150 questions (30 held out) of 5 kinds: single-hop, multi-hop, aggregation, fuzzy, unanswerable. Correct answers are produced by running a Cypher query on the graph, never typed by hand. **DONE**: `evals/gold/questions.jsonl`, 12 questions on AI techniques, a stratified test split and 168 tests | The graph | none (questions written by us) | `evals/gold/questions.jsonl` |
| **P4 Baselines** | Build the two systems we must beat: (a) vector-only RAG, (b) graph-only Text2Cypher. Build the scorer: ID precision/recall/F1, latency, tokens, $/query | Graph + vectors; gold set | bge-small; Groq LLM | Baseline results table by question type |
| **P5 MCP server** | Expose the graph as 6 safe, read-only tools. Guardrails: read-only transactions, keyword deny-list, 5 s timeout, row cap, bounded path lengths, audit log | Graph | none | Tested server |
| **P6 Agent** | LangGraph state machine with routing, citations, budgets (max 8 tool calls) and a deterministic citation check | Graph via MCP | Groq LLM, bge-small (names resolved by the full-text index first, vectors second) | Agent returning answer + citations + paths + cost + latency |
| **P7 Evaluation** | Compare vector-RAG vs Text2Cypher vs the agent; error analysis; ablations; one final run on the held-out 30 | Gold set | Groq LLM (and optionally one API model) | `rag_comparison.md` |
| **P8 Fine-tune data** | Build `{text → JSON}` training examples; split **by document**, never by sentence; hand-verify the test set | ATT&CK procedure text, AnnoCTR | none (no model calls were needed) | Train/val/test JSONL. **DONE**: 4,423 train / 265 validation / 226 + 600 test |
| **P9 QLoRA** | Fine-tune Qwen3-1.7B on Kaggle | P8 dataset | Qwen3-1.7B + LoRA | Adapter on Hugging Face Hub |
| **P10 Extractor eval** | Compare base, fine-tuned, fine-tuned + constrained decoding, and an API model on entity F1, technique F1, relation F1, JSON validity, hallucinated IDs, latency, cost | Hand-verified test set; the graph (to check IDs exist) | The models listed | `extractor_comparison.md` |
| **P11 Integration** | Convert to GGUF, serve with Ollama, `make ingest-report URL=...`; link extracted entities to graph nodes; mark unmatched ones provisional | New threat reports | Extractor (GGUF), bge-small for linking | Graph updated from raw reports |
| **P12 UI / demo** | Gradio app: Ask, Extract, Benchmarks tabs; evidence-path graph view; deployed on a free HF Space with a subset graph | Subset graph; benchmark tables | Groq LLM for the agent; extractor on CPU | Public demo link |
| **P13 Quality** | Fixture-based tests, CI, Dockerfile, `make update`, structured logs | Small fixture files | mocked LLM in tests | Green CI |
| **P14 Write-up** | README with results, "what failed", "when fine-tuning was and wasn't worth it", resume bullet | All result tables | none | Published repo |

---

## 8. Honest significance and limits

**What is genuinely real and useful**
- The data is real, current and authoritative (MITRE, NIST, CISA). The graph can answer questions that are tedious to answer by hand.
- Every answer is **checkable**: citations point to real graph paths and a deterministic check rejects cited IDs that aren't in the evidence.
- The techniques (knowledge graphs, agentic routing, MCP tooling, fine-tuning for structured extraction, evaluation with hard numbers) are the techniques used in real GenAI systems.

**What it is not**
- Not a detection product, SIEM or SOC platform; it doesn't ingest your logs.
- Not a source of new intelligence; it organises and cross-links existing public knowledge, plus whatever the extractor pulls from reports you give it.
- Coverage is limited by the sources. For example, not every ATT&CK technique has a CAPEC mapping, and not every CVE has a CWE. The data-quality report measures this, and low coverage is reported as a finding.

**Honest caveats about the evaluation**
- Gold answers come from Cypher over the graph, so the benchmark measures "can the system retrieve what the graph contains", not "does it help a real analyst". That is a fair test of retrieval, but a limited one.
- The free Groq tier has rate limits, so evaluation runs must be resumable and cached.
- The extractor's test set is small (50–100 hand-verified chunks), so its F1 numbers carry wide uncertainty and should be reported that way.

**The claims the project will back with numbers**
1. Agentic hybrid retrieval beats vector-only RAG on multi-hop questions (F1 on the gold set).
2. Answers are faithful: cited IDs exist in the graph and support the claim.
3. The fine-tuned 1.7B extractor approaches an API model's quality at a fraction of the cost.
4. The system runs within a stated cost per query and p95 latency.

If any claim doesn't hold, the README reports it anyway. A clear negative result is still a useful result.
