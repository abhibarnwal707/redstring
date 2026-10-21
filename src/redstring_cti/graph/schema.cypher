CREATE CONSTRAINT group_id   IF NOT EXISTS FOR (n:Group)     REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT tech_id    IF NOT EXISTS FOR (n:Technique) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT tactic_id  IF NOT EXISTS FOR (n:Tactic)    REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT sw_id      IF NOT EXISTS FOR (n:Software)  REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT mit_id     IF NOT EXISTS FOR (n:Mitigation) REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT camp_id    IF NOT EXISTS FOR (n:Campaign)  REQUIRE n.attack_id IS UNIQUE;
CREATE CONSTRAINT capec_id   IF NOT EXISTS FOR (n:CAPEC)     REQUIRE n.capec_id IS UNIQUE;
CREATE CONSTRAINT cwe_id     IF NOT EXISTS FOR (n:CWE)       REQUIRE n.cwe_id IS UNIQUE;
CREATE CONSTRAINT cve_id     IF NOT EXISTS FOR (n:CVE)       REQUIRE n.cve_id IS UNIQUE;
CREATE CONSTRAINT searchable_uid IF NOT EXISTS FOR (n:Searchable) REQUIRE n.uid IS UNIQUE;
// Retired: one mixed vector index let 394K CVEs crowd out the 3.3K ATT&CK/CAPEC/CWE concept nodes.
DROP INDEX searchable_vec IF EXISTS;
// Replaced by text_search, which also indexes aliases (needed to resolve "Cozy Bear" -> APT29).
DROP INDEX searchable_text IF EXISTS;
CREATE FULLTEXT INDEX text_search IF NOT EXISTS
  FOR (n:Group|Technique|Software|Mitigation|Campaign|CAPEC|CWE|CVE) ON EACH [n.name, n.description, n.aliases];
// Concepts (every non-CVE node carries :Reference) and CVEs are searched separately.
CREATE VECTOR INDEX ref_vec IF NOT EXISTS FOR (n:Reference) ON n.embedding
  OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}};
CREATE VECTOR INDEX cve_vec IF NOT EXISTS FOR (n:CVE) ON n.embedding
  OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}};
