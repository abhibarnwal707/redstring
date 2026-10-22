---
license: other
pretty_name: RedString-CTI graph (Neo4j dump)
tags: [neo4j, knowledge-graph, cyber-threat-intelligence, mitre-attack]
---
# RedString-CTI graph (Neo4j 5 dump)

A Neo4j 5 Community database dump (`neo4j.dump`, about 690 MB) of the knowledge graph used by
[RedString-CTI](https://github.com/abhibarnwal707/redstring): 109,515 nodes and 154,535 relationships, with 384-dimensional
`BAAI/bge-small-en-v1.5` embeddings (MIT licence), two vector indexes and a full-text index.
Restore it with `make graph-restore` in the project (or `neo4j-admin database load neo4j --from-path=<folder with neo4j.dump>`).

**What it holds.** MITRE ATT&CK v20 (groups, techniques, tactics, software, mitigations, campaigns), CAPEC 3.9, CWE 4.20, the CVEs
that are on the CISA KEV list or reachable from a technique through CAPEC and CWE (106,111 of the 393,847 non-rejected NVD CVEs),
and three CISA advisories ingested by the project's extractor (marked `Report` / `ProvisionalEntity`, unverified).
All 150 questions of the project's gold set have the same answers on this subset as on the full graph.

**Sources and terms.** MITRE ATT&CK, CAPEC and CWE are provided by The MITRE Corporation under its terms of use (free to use with
the copyright notice, https://attack.mitre.org/resources/terms-of-use/); NVD data is a US government work; the CISA KEV catalogue
is published by CISA. Check each source's terms for your own use. Report-derived content is automatic and unverified.
