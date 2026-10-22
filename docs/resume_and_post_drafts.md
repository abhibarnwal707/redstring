# Resume bullets and post: drafts (every number below is measured; items in [brackets] are pending)

## Resume bullets (pick 3-4)
- Built **RedString-CTI**, an agentic GraphRAG system for cyber threat intelligence: a 397K-node Neo4j knowledge graph unifying MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV, queried through a read-only **MCP server** (8 tools, read-transaction and deny-list guardrails, audit log) by a **LangGraph** agent that cites graph IDs and checks every citation against retrieved evidence.
- Created a 150-question evaluation set whose answers are computed from the graph (single-hop, multi-hop, aggregation, semantic, unanswerable) and showed that plain vector RAG answers **13.8%** of 109 dev questions against **79.8%** for Text2Cypher, with the gap concentrated on relationship questions that text-only retrieval cannot answer; [agent result: X% on the same questions, held-out test: Y%].
- **QLoRA fine-tuned Qwen3-1.7B** (Kaggle T4) to extract entities, ATT&CK technique IDs and relations from threat reports: on 78 held-out real-report chunks it scores **0.605 entity F1 / 0.597 technique F1** against **0.316 / 0.448** for a zero-shot 120B API model, with 100% valid JSON and 0% invented ATT&CK IDs under schema-constrained decoding; the 1.7 GB quantised build runs on a laptop at about 1-4 s per chunk with no API cost.
- Wrote honest negative results into the repo: the first fine-tune (2 epochs) was **not** worth it (technique F1 0.222 vs 0.597 after the second run), 60% of real-report technique IDs are written verbatim in the text, and recall on IDs that must be inferred is 21%.
- Engineered for reproducibility: one-command local setup (`make quickstart`: Dockerised Neo4j, a published graph dump, a published model), 507 tests, CI with an integration job, resumable evaluation runs that survive free-tier rate limits, and report ingestion that never overwrites curated data (provisional nodes and a separate `ASSERTED` relation).

## Post (LinkedIn), about 200 words
I built a threat-intelligence assistant that has to show its work, and the most useful thing I learned is where it did NOT work.

RedString-CTI links MITRE ATT&CK, CAPEC, CWE, NVD and CISA KEV into one Neo4j graph. A LangGraph agent answers questions through a read-only MCP server and cites IDs it actually retrieved. On 109 dev questions, vector-only RAG got 13.8% right and Text2Cypher 79.8%: relationships are the whole point of a graph. [Agent result: pending.]

I also fine-tuned a 1.7B model to read threat reports. My first run was not worth it. After more data and training it beat a zero-shot 120B model on entities and ATT&CK technique IDs (0.605 vs 0.316, 0.597 vs 0.448 on 78 held-out report chunks), with 100% valid JSON and no invented IDs. Then I checked why: 60% of the technique IDs are written out in the text, and recall on the ones that need inference is only 21%. The numbers are real, and so are the limits.

Everything runs locally: `make quickstart` sets up Neo4j, the graph and the model. Code, results and failure analyses: [repo link]

#cybersecurity #threatintelligence #graphrag #llm #mitreattack
