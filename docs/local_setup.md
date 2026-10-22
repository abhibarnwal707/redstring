# Running RedString-CTI on your own computer

## What runs where
| Piece | What it is | How you get it |
|---|---|---|
| **Neo4j** (the graph database) | Holds the knowledge graph: ATT&CK, CAPEC, CWE, CVEs, CISA KEV | Runs in a Docker container started by `docker-compose.yml`. You install **only Docker**; there is nothing to configure by hand. |
| **The graph data** | 109,515 nodes, 154,535 relationships, with embeddings | Downloaded as a ready-made dump (about 700 MB) from Hugging Face by `make quickstart` and loaded into Neo4j. |
| **The extractor model** | Our fine-tuned Qwen3-1.7B (reads a threat report, returns entities, ATT&CK techniques and relations) | Downloaded as a 1.8 GB quantised file from Hugging Face and registered with **Ollama**. You do not train anything. |
| **The agent's language model** | Answers questions using the graph | A free **Groq** API key (online). Only the Ask tab needs it. |
| **The app** | Gradio web page on `localhost:7860` | `make app` |

## Requirements
| | Minimum | Recommended |
|---|---|---|
| RAM | 8 GB (give Docker at least 4 GB; set `NEO4J_HEAP=1G` and `NEO4J_PAGECACHE=1G` in `.env`) | 16 GB |
| Free disk | 15 GB (Python dependencies 3, graph 3, model 2, caches 2) | 25 GB |
| CPU | 4 cores, x86_64 or arm64 | Apple Silicon or a recent desktop CPU |
| GPU | not needed | not needed |
| OS | macOS or Linux; Windows through WSL2 | |
| Software | Docker Desktop, uv, Ollama, git | |

**What was tested.** Everything was developed and run on one machine: a MacBook with Apple Silicon (arm64), 17 GB RAM, macOS,
Docker Desktop 29, Ollama 0.40. A clean-room run of `make quickstart` (fresh folder, no `.env`, anonymous downloads) passed there.
**Not tested:** Windows/WSL2, Linux, x86_64 machines, and machines with 8 GB RAM. The minimums above are estimates from the measured
memory use (Neo4j with its default 2 GB heap and 2 GB page cache, the embedding model, and the extractor).

**Speed you can expect.** On the Apple-Silicon laptop the extractor takes about 1-4 seconds per chunk. On a CPU-only machine it is much slower:
in a Docker container limited to 2 CPUs it took about 21 seconds for a two-sentence report and 44 seconds for a full 1,400-character chunk.
Graph questions answer in a few seconds; the Groq free tier adds waiting when many questions are asked in a row (about 100 questions a day
on the free token allowance, measured at 1.5-3K tokens per question).

## Step by step
1. **Install the tools** (once): [Docker Desktop](https://docs.docker.com/get-docker/) (start it), [uv](https://docs.astral.sh/uv/getting-started/installation/),
   [Ollama](https://ollama.com/download) (start it), git.
2. **Get the code and dependencies:** `git clone https://github.com/abhibarnwal707/redstring.git && cd redstring && uv sync`
3. **`make doctor`**: prints OK / WARN / FAIL for RAM, disk, Docker, Ollama, ports and `.env`. Fix any FAIL.
4. **`make quickstart`**:
   1. creates `.env` with a random Neo4j password;
   2. downloads the graph dump and loads it into Neo4j with `neo4j-admin database load`, then starts the container (`docker compose up -d neo4j`);
   3. downloads the model and runs `ollama create redstring-extractor`;
   4. runs a smoke test: it asks the graph for "Cozy Bear", follows paths to actively exploited CVEs, and extracts from one sentence.
5. **Get a Groq key** (free, only for the Ask tab): https://console.groq.com/keys, then add `GROQ_API_KEY=...` to `.env`.
6. **`make app`** and open http://localhost:7860.

You can look at the graph yourself in the Neo4j Browser at http://localhost:7474 (user `neo4j`, the password is in `.env`).

## Troubleshooting
| Symptom | Fix |
|---|---|
| `docker: ... daemon is not running` | Start Docker Desktop and wait until it says it is running. |
| Port 7687 or 7474 already in use | You may have another Neo4j. Set `NEO4J_BOLT_PORT` / `NEO4J_HTTP_PORT` in `.env` and set `NEO4J_URI=bolt://localhost:<bolt port>`. |
| `make graph-restore` says "already holds a database" | It never overwrites a graph. Use `make graph-restore ARGS=--force` to replace it. |
| I changed `NEO4J_PASSWORD` and Neo4j rejects it | Neo4j keeps the password from its first start. Restore again with `ARGS=--force` (or `make down` and delete `data/neo4j`). |
| Neo4j keeps restarting or is killed | Docker has too little memory: raise it in Docker Desktop settings (at least 4 GB) and lower `NEO4J_HEAP` / `NEO4J_PAGECACHE` to `1G`. |
| Extract tab: "connection refused" | Ollama is not running: open the Ollama app or run `ollama serve`, then `make model-fetch`. |
| Extract tab is very slow | Normal on a CPU-only machine. Paste a shorter text; the demo processes the first 3 chunks (`REDSTRING_MAX_CHUNKS`). |
| Ask tab says it needs a Groq key | Add `GROQ_API_KEY` to `.env` and restart `make app`. |
| Ask tab: rate limit / "daily quota" | The free Groq token allowance is used up; wait for it to reset (about a day). |
| Linux: permission denied on `data/neo4j` | Docker wrote the folder as another user: `sudo chown -R $USER data/neo4j` (untested). |
| No Ollama available | Set `REDSTRING_EXTRACTOR=hf` in `.env`: it downloads the base model and our adapter (about 4 GB) and runs through PyTorch; slower and heavier. |

## Rebuilding things yourself (optional)
- **The graph from the public sources** instead of the dump: `make download && make load && make embed` (about an hour, about 15 GB). This builds the *full* graph (397,191 nodes); the dump is a subset that answers all 150 evaluation questions identically.
- **The model:** the adapter is on the Hub (`abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-lora-v2`); `make ollama-model` re-creates the quantised files (needs Docker). Training used Kaggle (`finetune/notebooks/train_qlora.py`).

## Cleaning up
`make down` stops Neo4j. To remove everything: delete the `data/` folder, `ollama rm redstring-extractor`, and `docker image rm neo4j:5-community`.
