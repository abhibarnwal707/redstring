# Demo script (about three minutes)

Prepare: `make up`, `ollama` running, `make app`, browser at http://localhost:7860. Screen recording on macOS: Shift-Cmd-5.

**1. The graph (20 s).** Open http://localhost:7474 and run `MATCH (g:Group {name:'APT29'})-[:USES]->(t:Technique) RETURN g,t LIMIT 25`.
Say: ATT&CK, CAPEC, CWE, NVD and CISA KEV in one graph, 109,515 nodes in this demo build.

**2. Ask tab: single-hop (30 s).** "Which techniques does APT29 use?" Show the answer with cited IDs and the trace under it (route, tool calls, tokens, cost).

**3. Ask tab: multi-hop (40 s).** "Which actively exploited (KEV) CVEs are weakness-linked, through CAPEC and CWE, to the techniques of Sandworm Team?"
Point at the note that this means *shares a weakness*, not *group exploited the CVE*.

**4. Ask tab: refusing to guess (20 s).** "What is the EPSS score of CVE-2024-0001?" The graph does not hold it, so the agent says so.

**5. Extract tab (45 s).** Paste the sample report (or a paragraph from a real advisory). Show entities linked to graph IDs, the techniques, and the one
entity that is "not in the graph (would be provisional)". Say: this is our fine-tuned 1.7B model running locally through Ollama.

**6. Reports against ATT&CK (30 s).** Ask "What does the Royal advisory add beyond ATT&CK about Royal?" (the three CISA advisories are already ingested).
Say: report claims are stored separately from curated ATT&CK and marked unverified.

**7. Benchmarks tabs (15 s).** Show the extractor comparison table and the "Fine-tuning verdict" page.

All questions above were checked against the graph; the Ask tab needs a Groq key and some daily token allowance.
