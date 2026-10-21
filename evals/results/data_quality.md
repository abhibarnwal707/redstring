# Data-quality report
Generated 2026-10-21 11:36 UTC by `make dq` from the live graph and the raw files in `data/raw/`.

## 1. Sources and versions
| Source | Version / snapshot |
|---|---|
| MITRE ATT&CK Enterprise | 20.0 |
| CWE | 4.20 |
| CAPEC | 3.9 |
| NVD CVE JSON 2.0 | 26 feeds (yearly + modified); modified-feed snapshot 2026-10-21T01:00:06.5311202 |
| CISA KEV | catalog 2026.10.20, 1,754 entries |

## 2. What is in the graph
**Nodes**

| Label | Count |
|---|---|
| CVE | 393,847 |
| CWE | 944 |
| Software | 842 |
| Technique | 706 |
| CAPEC | 558 |
| Group | 178 |
| Campaign | 57 |
| Mitigation | 44 |
| Tactic | 15 |

**Edges**

| Relationship | Count |
|---|---|
| HAS_WEAKNESS | 356,306 |
| USES | 18,975 |
| CHILD_OF | 1,692 |
| MITIGATES | 1,477 |
| EXPLOITS | 1,211 |
| IN_TACTIC | 881 |
| SUBTECHNIQUE_OF | 479 |
| MAPS_TO | 256 |
| ATTRIBUTED_TO | 26 |

Total: 397,191 nodes, 381,303 edges.

## 3. Skipped or dropped during ingestion

Revoked or deprecated objects are removed on purpose; counts are recomputed from the raw files.

| Source | Item | Count |
|---|---|---|
| ATT&CK | edges_dropped_endpoint_not_live:SUBTECHNIQUE_OF | 2 |
| ATT&CK | skipped_deprecated:attack-pattern | 12 |
| ATT&CK | skipped_deprecated:course-of-action | 224 |
| ATT&CK | skipped_deprecated:intrusion-set | 9 |
| ATT&CK | skipped_deprecated:malware | 1 |
| ATT&CK | skipped_revoked:attack-pattern | 149 |
| ATT&CK | skipped_revoked:intrusion-set | 6 |
| ATT&CK | skipped_revoked:malware | 2 |
| CWE | skipped_deprecated:Weakness | 25 |
| CAPEC | skipped_deprecated:Attack_Pattern | 56 |
| CAPEC | skipped_obsolete:Attack_Pattern | 1 |
| CAPEC | ATT&CK mappings parsed | 271 |
| CAPEC | mappings dropped (technique revoked or deprecated) | 15 |
| NVD | records read across all feeds (modified overlaps yearly) | 415,741 |
| NVD | CVEs kept (distinct) | 393,847 |
| NVD | CVEs skipped as Rejected (distinct) | 18,618 |
| NVD | CWE ids referenced by CVEs but absent from the graph (distinct) | 53 |
| NVD | CVE-to-CWE references dropped for that reason | 14,541 |

## 4. Orphans (nodes with no relationships)

| Label | Orphans | Of |
|---|---|---|
| CVE | 75,152 | 393,847 |
| CAPEC | 2 | 558 |

A CVE with no relationships is one with no usable CWE (see section 5). Labels not listed have no orphans.

## 5. Coverage: how well the sources connect

### CAPEC to ATT&CK (the bridge between attacker behaviour and weaknesses)

| Measure | Value |
|---|---|
| Techniques with at least one CAPEC mapping | 179 of 706 (25.4%) |
| ...top-level techniques | 84 of 227 (37.0%) |
| ...sub-techniques | 95 of 479 (19.8%) |
| CAPEC patterns mapped to at least one technique | 175 of 558 (31.4%) |
| CAPEC patterns linked to at least one CWE | 449 of 558 (80.5%) |
| Group-to-technique edges whose technique has a CAPEC mapping | 1,648 of 4,815 (34.2%) |
| APT29 techniques with a CAPEC mapping | 20 of 66 (30.3%) |

ATT&CK v20 techniques carry no CAPEC references of their own, so every `MAPS_TO` edge comes from CAPEC's taxonomy mappings.

### CVE to CWE

| Measure | Value |
|---|---|
| CVEs with a `HAS_WEAKNESS` edge | 318,695 of 393,847 (80.9%) |
| KEV CVEs with a `HAS_WEAKNESS` edge | 1,541 of 1,754 (87.9%) |
| CVEs listing only pseudo-weaknesses (NVD-CWE-Other / noinfo) | 53,505 of 393,847 (13.6%) |
| CVEs with no weakness data at all | 8,436 of 393,847 (2.1%) |
| CVEs whose only CWEs are missing from our graph | 13,211 of 393,847 (3.4%) |
| CVEs without any CVSS score | 4,016 of 393,847 (1.0%) |

CVSS version used: 3.1: 266,873, 2.0: 72,405, 3.0: 42,944, 4.0: 7,609, None: 4,016.

Most frequent CWE ids referenced by CVEs but absent from the graph: CWE-264 (5,513), CWE-399 (2,695), CWE-310 (2,530), CWE-189 (1,277), CWE-255 (785).

These are CWE *categories* (legacy groupings such as CWE-264 "Permissions, Privileges, and Access Controls"), not weaknesses; checked against CWE 4.20 for the ids above. The CWE ingester loads weaknesses only, so these references are dropped. Loading categories would recover those CVE links but would add nodes no CAPEC pattern points to, so it is left as an open decision.

### Full chain: Group, Technique, CAPEC, CWE, CVE

| Measure | Value |
|---|---|
| Groups using at least one technique | 174 of 178 (97.8%) |
| ...that reach a CAPEC pattern | 164 of 178 (92.1%) |
| ...that reach a CWE | 163 of 178 (91.6%) |
| ...that reach at least one CVE through the full chain | 163 of 178 (91.6%) |
| ...that reach at least one KEV CVE through the full chain | 162 of 178 (91.0%) |
| CVEs reachable from some technique through the chain | 104,860 of 393,847 (26.6%) |
| KEV CVEs reachable through the chain | 503 of 1,754 (28.7%) |

**How specific are the chain links?** The weakness a chain passes through decides how meaningful it is. A CVE with several weaknesses is counted once per abstraction level, so the rows add up to more than the total above.

| CWE abstraction level | CVEs reached through it |
|---|---|
| Class | 65,151 |
| Base | 32,497 |
| Pillar | 9,330 |
| Variant | 1,108 |
| Compound | 466 |

Weaknesses most often on the chain:

| CWE | Name | Abstraction | CVEs |
|---|---|---|---|
| CWE-20 | Improper Input Validation | Class | 13,601 |
| CWE-200 | Exposure of Sensitive Information to an Unauthorized Actor | Class | 11,465 |
| CWE-862 | Missing Authorization | Class | 11,018 |
| CWE-284 | Improper Access Control | Pillar | 8,190 |
| CWE-94 | Improper Control of Generation of Code ('Code Injection') | Base | 7,492 |
| CWE-74 | Improper Neutralization of Special Elements in Output Used by a Downst | Class | 5,647 |
| CWE-287 | Improper Authentication | Class | 5,160 |
| CWE-434 | Unrestricted Upload of File with Dangerous Type | Base | 4,526 |

## 6. Embedding coverage

| Label | With vector | Total |
|---|---|---|
| CVE | 106,111 | 393,847 |
| CWE | 944 | 944 |
| Software | 842 | 842 |
| Technique | 706 | 706 |
| CAPEC | 558 | 558 |
| Group | 178 | 178 |
| Campaign | 57 | 57 |
| Mitigation | 44 | 44 |
| Tactic | 15 | 15 |

Every concept node is embedded. CVEs are embedded only when they are KEV or on the chain above; the rest are found through the full-text index or by ID.

## 7. What this means for multi-hop answers

- **The chain is sparse at its bridge.** Only 25.4% of techniques have a CAPEC mapping, so a question that needs Technique to CAPEC can be answered for only that share of techniques. This is a property of the sources, not a bug.
- **Most CVEs sit off the chain.** 104,860 of 393,847 (26.6%) are reachable from a technique; the remainder have no CWE, a CWE no mapped CAPEC pattern exploits, or only a pseudo-weakness.
- **Chain links are weakness-level, not observed exploitation.** A group reaching a CVE means the group uses a technique that a CAPEC pattern ties to a weakness that CVE also has. Answers must say so, and must not claim the group used that CVE.
- **Generic weaknesses inflate the chain.** The abstraction table shows how many CVEs are reached only through broad Class/Pillar weaknesses; those links are the weakest.
- **Direct evidence lives in text.** Statements such as "APT29 exploited CVE-2019-19781" appear in `USES` descriptions and threat reports, which is the job of the fine-tuned extractor.
