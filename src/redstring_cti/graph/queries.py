"""Named Cypher queries used by the graph sanity tests (and later the agent's templates)."""

from typing import Any

# name -> (cypher, params, minimum expected rows)
SANITY_QUERIES: dict[str, tuple[str, dict[str, Any], int]] = {
    "apt29_techniques": (
        "MATCH (:Group {attack_id: $gid})-[:USES]->(t:Technique) RETURN t.attack_id AS id",
        {"gid": "G0016"},
        60,
    ),
    "subtechniques_of_t1059": (
        "MATCH (s:Technique)-[:SUBTECHNIQUE_OF]->(:Technique {attack_id: $tid}) RETURN s.attack_id AS id",
        {"tid": "T1059"},
        5,
    ),
    "mitigations_for_phishing": (
        "MATCH (m:Mitigation)-[:MITIGATES]->(:Technique {attack_id: $tid}) RETURN m.attack_id AS id",
        {"tid": "T1566"},
        1,
    ),
    "software_used_by_apt29": (
        "MATCH (:Group {attack_id: $gid})-[:USES]->(s:Software) RETURN s.attack_id AS id",
        {"gid": "G0016"},
        10,
    ),
    "tactics_of_technique": (
        "MATCH (:Technique {attack_id: $tid})-[:IN_TACTIC]->(t:Tactic) RETURN t.shortname AS id",
        {"tid": "T1566.001"},
        1,
    ),
    "v19_split_tactics_exist": (
        "MATCH (t:Tactic) WHERE t.shortname IN ['stealth', 'defense-impairment'] RETURN t.attack_id AS id",
        {},
        2,
    ),
    "cwes_exploited_by_capec_66": (
        "MATCH (:CAPEC {capec_id: $cid})-[:EXPLOITS]->(w:CWE) RETURN w.cwe_id AS id",
        {"cid": "CAPEC-66"},
        2,
    ),
    "techniques_mapped_from_spear_phishing": (
        "MATCH (:CAPEC {capec_id: $cid})-[:MAPS_TO]->(t:Technique) RETURN t.attack_id AS id",
        {"cid": "CAPEC-163"},
        5,
    ),
    "cwe_parents_of_sql_injection": (
        "MATCH (:CWE {cwe_id: $wid})-[:CHILD_OF]->(p:CWE) RETURN p.cwe_id AS id",
        {"wid": "CWE-89"},
        2,
    ),
    "apt29_techniques_with_a_capec_pattern": (
        """MATCH (:Group {attack_id: $gid})-[:USES]->(t:Technique)<-[:MAPS_TO]-(c:CAPEC)
           RETURN DISTINCT t.attack_id AS id""",
        {"gid": "G0016"},
        15,
    ),
    "groups_sharing_5_techniques_with_apt29": (
        """MATCH (:Group {attack_id: $gid})-[:USES]->(t:Technique)<-[:USES]-(o:Group)
           WHERE o.attack_id <> $gid
           WITH o, count(DISTINCT t) AS shared WHERE shared >= 5
           RETURN o.attack_id AS id, shared""",
        {"gid": "G0016"},
        5,
    ),
    "most_used_techniques": (
        """MATCH (g:Group)-[:USES]->(t:Technique)
           RETURN t.attack_id AS id, count(DISTINCT g) AS groups ORDER BY groups DESC LIMIT 10""",
        {},
        10,
    ),
}
