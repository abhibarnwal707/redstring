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
CREATE FULLTEXT INDEX searchable_text IF NOT EXISTS
  FOR (n:Group|Technique|Software|Mitigation|CAPEC|CWE|CVE) ON EACH [n.name, n.description];
CREATE VECTOR INDEX searchable_vec IF NOT EXISTS FOR (n:Searchable) ON n.embedding
  OPTIONS {indexConfig: {`vector.dimensions`: 384, `vector.similarity_function`: 'cosine'}};
