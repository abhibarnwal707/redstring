"""The 150 gold questions (hand-written questions + Cypher; gold answers come from running the Cypher).

Append new questions at the END of a block's list only: ids are assigned by position, so reordering
renumbers everything. Conventions for the Cypher:
  * list questions return one column `id` (DISTINCT, ordered); ranked lists also return `value`
    and use `LIMIT {limit}`; count questions return one column `value`.
  * unanswerable questions return NO rows (proof the graph lacks the answer); `precondition` returns
    rows when the entity the question is about does exist.
Chain questions (Group/Technique -> CAPEC -> CWE -> CVE) are worded as what the path really means:
a weakness-level association, never "the group used this CVE".
"""

from dataclasses import dataclass, field

from redstring_cti.gold.models import AnswerStyle, QuestionType


@dataclass(frozen=True)
class QuestionSpec:
    question: str
    type: QuestionType
    hops: int
    cypher: str
    style: AnswerStyle = "list"
    tags: frozenset[str] = field(default_factory=frozenset)
    notes: str = ""
    ranked_n: int | None = None
    precondition: str | None = None


def _tags(*t: str) -> frozenset[str]:
    return frozenset(t)


# ---------------------------------------------------------------- Cypher building blocks
def mitigations_of(tid: str) -> str:
    return f"MATCH (m:Mitigation)-[:MITIGATES]->(:Technique {{attack_id: '{tid}'}}) RETURN DISTINCT m.attack_id AS id ORDER BY id"


def subtechniques_of(tid: str) -> str:
    return f"MATCH (s:Technique)-[:SUBTECHNIQUE_OF]->(:Technique {{attack_id: '{tid}'}}) RETURN DISTINCT s.attack_id AS id ORDER BY id"


def tactics_of(tid: str) -> str:
    return f"MATCH (:Technique {{attack_id: '{tid}'}})-[:IN_TACTIC]->(x:Tactic) RETURN DISTINCT x.attack_id AS id ORDER BY id"


def software_of_group(gid: str) -> str:
    return f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(s:Software) RETURN DISTINCT s.attack_id AS id ORDER BY id"


def group_tactic_techniques(gid: str, tactic: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(t:Technique)-[:IN_TACTIC]->(:Tactic {{shortname: '{tactic}'}}) "
        "RETURN DISTINCT t.attack_id AS id ORDER BY id"
    )


def group_software_with_technique(gid: str, tid: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(s:Software)-[:USES]->(:Technique {{attack_id: '{tid}'}}) "
        "RETURN DISTINCT s.attack_id AS id ORDER BY id"
    )


def campaign_group_software(cid: str) -> str:
    return (
        f"MATCH (:Campaign {{attack_id: '{cid}'}})-[:ATTRIBUTED_TO]->(:Group)-[:USES]->(s:Software) "
        "RETURN DISTINCT s.attack_id AS id ORDER BY id"
    )


def group_tactic_mitigations(gid: str, tactic: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(t:Technique)-[:IN_TACTIC]->(:Tactic {{shortname: '{tactic}'}}) "
        "WITH DISTINCT t MATCH (m:Mitigation)-[:MITIGATES]->(t) RETURN DISTINCT m.attack_id AS id ORDER BY id"
    )


def shared_techniques(a: str, b: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{a}'}})-[:USES]->(t:Technique)<-[:USES]-(:Group {{attack_id: '{b}'}}) "
        "RETURN DISTINCT t.attack_id AS id ORDER BY id"
    )


def group_capec(gid: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(:Technique)<-[:MAPS_TO]-(c:CAPEC) "
        "RETURN DISTINCT c.capec_id AS id ORDER BY id"
    )


def technique_cwes(tid: str) -> str:
    return (
        f"MATCH (:Technique {{attack_id: '{tid}'}})<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(w:CWE) "
        "RETURN DISTINCT w.cwe_id AS id ORDER BY id"
    )


def cwe_techniques(wid: str) -> str:
    return (
        f"MATCH (t:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE {{cwe_id: '{wid}'}}) "
        "RETURN DISTINCT t.attack_id AS id ORDER BY id"
    )


def technique_kev_cves(tid: str) -> str:
    return (
        f"MATCH (:Technique {{attack_id: '{tid}'}})<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)"
        "<-[:HAS_WEAKNESS]-(v:CVE {kev: true}) RETURN DISTINCT v.cve_id AS id ORDER BY id"
    )


def group_kev_cves(gid: str, where: str) -> str:
    return (
        f"MATCH (:Group {{attack_id: '{gid}'}})-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)"
        f"<-[:HAS_WEAKNESS]-(v:CVE {{kev: true}}) WHERE {where} RETURN DISTINCT v.cve_id AS id ORDER BY id"
    )


def cve_techniques(cve: str) -> str:
    return (
        f"MATCH (:CVE {{cve_id: '{cve}'}})-[:HAS_WEAKNESS]->(:CWE)<-[:EXPLOITS]-(:CAPEC)-[:MAPS_TO]->(t:Technique) "
        "RETURN DISTINCT t.attack_id AS id ORDER BY id"
    )


def cwe_groups(wid: str) -> str:
    return (
        f"MATCH (g:Group)-[:USES]->(:Technique)<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE {{cwe_id: '{wid}'}}) "
        "RETURN DISTINCT g.attack_id AS id ORDER BY id"
    )


def concepts(ids: list[str]) -> str:
    quoted = ", ".join(f"'{i}'" for i in ids)
    return (
        "MATCH (n:Reference) WITH n, coalesce(n.attack_id, n.cwe_id, n.capec_id) AS key "
        f"WHERE key IN [{quoted}] RETURN DISTINCT key AS id ORDER BY id"
    )


def concepts_prefix(prefix: str) -> str:
    return (
        "MATCH (t:Technique) WITH t WHERE t.attack_id STARTS WITH "
        f"'{prefix}' RETURN DISTINCT t.attack_id AS id ORDER BY id"
    )


def S(q: str, cy: str, *, hops: int = 1, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "single_hop", hops, cy, tags=tags, notes=notes)


def M(q: str, cy: str, hops: int, *, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "multi_hop", hops, cy, tags=tags, notes=notes)


def RANK(q: str, cy: str, n: int, hops: int, *, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "aggregation", hops, cy, style="ranked_list", ranked_n=n, tags=tags, notes=notes)


def COUNT(q: str, cy: str, hops: int, *, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "aggregation", hops, cy, style="count", tags=tags, notes=notes)


def SEM(q: str, cy: str, *, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "semantic", 1, cy, tags=tags | {"fuzzy"}, notes=notes or "Gold set is a judgement call; scored leniently.")


def NOANSWER(q: str, cy: str, *, precondition: str | None = None, tags: frozenset[str] = frozenset(), notes: str = "") -> QuestionSpec:
    return QuestionSpec(q, "unanswerable", 0, cy, style="not_found", precondition=precondition, tags=tags, notes=notes)


AI = "ai_technique"

# ================================================================ single_hop (40)
SINGLE_HOP = [
    S("What mitigations exist for T1566 (Phishing)?", mitigations_of("T1566")),
    S("Which mitigations address the Command and Scripting Interpreter technique (T1059)?", mitigations_of("T1059")),
    S("List the mitigations for Valid Accounts (T1078).", mitigations_of("T1078")),
    S("Which mitigations apply to Exploit Public-Facing Application (T1190)?", mitigations_of("T1190")),
    S("What can be done to mitigate Data Encrypted for Impact (T1486)?", mitigations_of("T1486")),
    S("Which mitigations are listed for OS Credential Dumping (T1003)?", mitigations_of("T1003")),
    S("What mitigations exist for Brute Force (T1110)?", mitigations_of("T1110")),
    S("Which sub-techniques does Phishing (T1566) have?", subtechniques_of("T1566")),
    S("What are the sub-techniques of Scheduled Task/Job (T1053)?", subtechniques_of("T1053")),
    S("List the sub-techniques of OS Credential Dumping (T1003).", subtechniques_of("T1003")),
    S("Which sub-techniques fall under the Valid Accounts technique?", subtechniques_of("T1078"), tags=_tags("name_resolution")),
    S("Which tactics does Valid Accounts (T1078) belong to?", tactics_of("T1078")),
    S("Which tactics is Process Injection (T1055) used for?", tactics_of("T1055")),
    S("What tactic does Data Encrypted for Impact (T1486) belong to?", tactics_of("T1486")),
    S("Which tactic does Exploit Public-Facing Application belong to?", tactics_of("T1190"), tags=_tags("name_resolution")),
    S("What software does the group Transparent Tribe use?", software_of_group("G0134")),
    S("Which software is used by Andariel?", software_of_group("G0138")),
    S("Which tools and malware does Cobalt Group use?", software_of_group("G0080")),
    S("What software is associated with APT3?", software_of_group("G0022")),
    S("List the software used by Patchwork.", software_of_group("G0040")),
    S(
        "Which techniques does the tool PsExec use?",
        "MATCH (:Software {attack_id: 'S0029'})-[:USES]->(t:Technique) RETURN DISTINCT t.attack_id AS id ORDER BY id",
    ),
    S(
        "Which campaigns are attributed to APT29?",
        "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(:Group {attack_id: 'G0016'}) RETURN DISTINCT c.attack_id AS id ORDER BY id",
    ),
    S(
        "Which campaigns are attributed to Sandworm Team?",
        "MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(:Group {attack_id: 'G0034'}) RETURN DISTINCT c.attack_id AS id ORDER BY id",
    ),
    S(
        "Which weaknesses does CAPEC-66 (SQL Injection) exploit?",
        "MATCH (:CAPEC {capec_id: 'CAPEC-66'})-[:EXPLOITS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "Which CWEs are exploited by CAPEC-88 (OS Command Injection)?",
        "MATCH (:CAPEC {capec_id: 'CAPEC-88'})-[:EXPLOITS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "What weaknesses does the attack pattern CAPEC-63 target?",
        "MATCH (:CAPEC {capec_id: 'CAPEC-63'})-[:EXPLOITS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "What are the parent weaknesses of CWE-89 (SQL Injection)?",
        "MATCH (:CWE {cwe_id: 'CWE-89'})-[:CHILD_OF]->(p:CWE) RETURN DISTINCT p.cwe_id AS id ORDER BY id",
    ),
    S(
        "Which ATT&CK techniques map to CAPEC-163 (Spear Phishing)?",
        "MATCH (:CAPEC {capec_id: 'CAPEC-163'})-[:MAPS_TO]->(t:Technique) RETURN DISTINCT t.attack_id AS id ORDER BY id",
    ),
    S(
        "Which ATT&CK techniques does CAPEC-593 map to?",
        "MATCH (:CAPEC {capec_id: 'CAPEC-593'})-[:MAPS_TO]->(t:Technique) RETURN DISTINCT t.attack_id AS id ORDER BY id",
    ),
    S(
        "Which weaknesses is Log4Shell (CVE-2021-44228) associated with?",
        "MATCH (:CVE {cve_id: 'CVE-2021-44228'})-[:HAS_WEAKNESS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "What weakness is the MOVEit Transfer vulnerability CVE-2023-34362 classified under?",
        "MATCH (:CVE {cve_id: 'CVE-2023-34362'})-[:HAS_WEAKNESS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "Which CWE is CVE-2019-19781 mapped to?",
        "MATCH (:CVE {cve_id: 'CVE-2019-19781'})-[:HAS_WEAKNESS]->(w:CWE) RETURN DISTINCT w.cwe_id AS id ORDER BY id",
    ),
    S(
        "Which ATT&CK group is also known as Cozy Bear?",
        "MATCH (g:Group) WHERE 'Cozy Bear' IN g.aliases RETURN DISTINCT g.attack_id AS id ORDER BY id",
        tags=_tags("alias", "name_resolution"),
    ),
    S(
        "Which group goes by the name Fancy Bear?",
        "MATCH (g:Group) WHERE 'Fancy Bear' IN g.aliases RETURN DISTINCT g.attack_id AS id ORDER BY id",
        tags=_tags("alias", "name_resolution"),
    ),
    S(
        "Which ATT&CK techniques are named Spearphishing Attachment?",
        "MATCH (t:Technique {name: 'Spearphishing Attachment'}) RETURN DISTINCT t.attack_id AS id ORDER BY id",
        tags=_tags("name_resolution", "ambiguous_name"),
        notes="Two techniques share this name (T1566.001 Initial Access, T1598.002 Reconnaissance).",
    ),
    S("Which mitigations apply to Indirect Prompt Injection (T1698)?", mitigations_of("T1698"), tags=_tags(AI)),
    S("What mitigations exist for Direct Prompt Injection (T1699)?", mitigations_of("T1699"), tags=_tags(AI)),
    S("Which tactic does Query Public AI Services (T1682) belong to?", tactics_of("T1682"), tags=_tags(AI)),
    S(
        "Which groups use Query Public AI Services (T1682)?",
        "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T1682'}) RETURN DISTINCT g.attack_id AS id ORDER BY id",
        tags=_tags(AI),
    ),
    S(
        "Which groups use the Artificial Intelligence technique (T1588.007)?",
        "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T1588.007'}) RETURN DISTINCT g.attack_id AS id ORDER BY id",
        tags=_tags(AI),
    ),
]

# ================================================================ multi_hop (60)
_CHAIN_NOTE = "Weakness-level association via CAPEC and CWE, not evidence that the group used the CVE."
MULTI_HOP = [
    # group -> technique filtered by tactic (2 hops)
    M("Which techniques does APT29 use for initial access?", group_tactic_techniques("G0016", "initial-access"), 2),
    M("Which impact techniques does Lazarus Group use?", group_tactic_techniques("G0032", "impact"), 2),
    M("What initial access techniques are used by FIN7?", group_tactic_techniques("G0046", "initial-access"), 2),
    M("Which Impact-tactic techniques does Sandworm Team use?", group_tactic_techniques("G0034", "impact"), 2),
    M("Which credential access techniques does APT28 use?", group_tactic_techniques("G0007", "credential-access"), 2),
    M("Which collection techniques does OilRig use?", group_tactic_techniques("G0049", "collection"), 2),
    M("Which initial access techniques does Scattered Spider use?", group_tactic_techniques("G1015", "initial-access"), 2),
    M("Which initial access techniques does Kimsuky use?", group_tactic_techniques("G0094", "initial-access"), 2),
    # group -> software -> technique (2 hops)
    M("Which software used by FIN7 also implements PowerShell (T1059.001)?", group_software_with_technique("G0046", "T1059.001"), 2),
    M("Which software used by Sandworm Team uses Data Encrypted for Impact (T1486)?", group_software_with_technique("G0034", "T1486"), 2),
    M("Which software used by Wizard Spider uses Data Encrypted for Impact (T1486)?", group_software_with_technique("G0102", "T1486"), 2),
    M("Which software used by APT28 performs LSASS Memory credential dumping (T1003.001)?", group_software_with_technique("G0007", "T1003.001"), 2),
    M("Which software used by Kimsuky uses Spearphishing Attachment (T1566.001)?", group_software_with_technique("G0094", "T1566.001"), 2),
    M("Which software used by MuddyWater uses PowerShell (T1059.001)?", group_software_with_technique("G0069", "T1059.001"), 2),
    # campaign -> group -> software (2 hops)
    M("Which software is used by the group behind the Triton Safety Instrumented System Attack campaign?", campaign_group_software("C0030"), 2),
    M("Which software does the group responsible for campaign C0011 use?", campaign_group_software("C0011"), 2),
    M("Which software is used by the group behind the RedPenguin campaign?", campaign_group_software("C0056"), 2),
    # mitigations for a group's techniques within a tactic (3 hops)
    M("Which mitigations address the collection techniques OilRig uses?", group_tactic_mitigations("G0049", "collection"), 3),
    M("Which mitigations apply to the impact techniques used by Wizard Spider?", group_tactic_mitigations("G0102", "impact"), 3),
    M("Which mitigations address the impact techniques used by Lazarus Group?", group_tactic_mitigations("G0032", "impact"), 3),
    M("Which mitigations apply to the initial access techniques used by Scattered Spider?", group_tactic_mitigations("G1015", "initial-access"), 3),
    M("Which mitigations apply to the impact techniques Sandworm Team uses?", group_tactic_mitigations("G0034", "impact"), 3),
    # techniques two groups share (2 hops)
    M("Which techniques are used by both Transparent Tribe and Andariel?", shared_techniques("G0134", "G0138"), 2),
    M("Which techniques do Andariel and LAPSUS$ both use?", shared_techniques("G0138", "G1004"), 2),
    M("Which techniques do Transparent Tribe and Sidewinder have in common?", shared_techniques("G0134", "G0121"), 2),
    M("Which techniques are shared by APT3 and Patchwork?", shared_techniques("G0022", "G0040"), 2),
    # group -> technique -> CAPEC (2 hops)
    M("Which CAPEC attack patterns relate to techniques used by Transparent Tribe?", group_capec("G0134"), 2),
    M("Which attack patterns (CAPEC) map to techniques used by Andariel?", group_capec("G0138"), 2),
    M("Which CAPEC patterns are linked to techniques used by LAPSUS$?", group_capec("G1004"), 2),
    M("Which CAPEC patterns map to techniques that APT33 uses?", group_capec("G0064"), 2),
    # technique -> CAPEC -> CWE (2 hops)
    M("Through CAPEC, which weaknesses are associated with Spearphishing Attachment (T1566.001)?", technique_cwes("T1566.001"), 2),
    M("Through CAPEC, which CWEs relate to Password Guessing (T1110.001)?", technique_cwes("T1110.001"), 2),
    M("Which weaknesses are linked, via CAPEC, to Valid Accounts (T1078)?", technique_cwes("T1078"), 2),
    M("Which CWEs relate to Credentials In Files (T1552.001) via CAPEC patterns?", technique_cwes("T1552.001"), 2),
    M("Which CWEs are tied to Kerberoasting (T1558.003) through CAPEC mappings?", technique_cwes("T1558.003"), 2),
    # CWE -> CAPEC -> technique (2 hops)
    M("Which ATT&CK techniques relate, via CAPEC, to the hard-coded credentials weakness CWE-798?", cwe_techniques("CWE-798"), 2),
    M("Which techniques are linked through CAPEC to CWE-307 (Improper Restriction of Excessive Authentication Attempts)?", cwe_techniques("CWE-307"), 2),
    M("Which techniques map via CAPEC patterns that exploit CWE-287 (Improper Authentication)?", cwe_techniques("CWE-287"), 2),
    M("Which techniques are associated through CAPEC with CWE-94 (Code Injection)?", cwe_techniques("CWE-94"), 2),
    # technique -> CAPEC -> CWE -> KEV CVE (3 hops)
    M("Which CISA KEV CVEs have a weakness exploited by an attack pattern mapped to Valid Accounts (T1078)?", technique_kev_cves("T1078"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs share a weakness with a CAPEC pattern that maps to Brute Force (T1110)?", technique_kev_cves("T1110"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs have a weakness tied via CAPEC to OS Credential Dumping (T1003)?", technique_kev_cves("T1003"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs have a weakness linked through CAPEC to Credentials from Password Stores (T1555)?", technique_kev_cves("T1555"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs share a weakness with a CAPEC pattern mapped to Data from Cloud Storage (T1530)?", technique_kev_cves("T1530"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs have a weakness tied via CAPEC to Data from Information Repositories (T1213)?", technique_kev_cves("T1213"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    M("Which KEV CVEs have a weakness linked via CAPEC to Data from Local System (T1005)?", technique_kev_cves("T1005"), 3, tags=_tags("kev", "chain"), notes=_CHAIN_NOTE),
    # group -> technique -> CAPEC -> CWE -> KEV CVE, with a filter that keeps the answer small (4 hops)
    M(
        "Which KEV CVEs with known ransomware use have a weakness tied via CAPEC to techniques used by Transparent Tribe?",
        group_kev_cves("G0134", "v.known_ransomware_use = true"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    M(
        "Which ransomware-linked KEV CVEs share a weakness with CAPEC patterns mapped to techniques Andariel uses?",
        group_kev_cves("G0138", "v.known_ransomware_use = true"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    M(
        "Which KEV CVEs used in ransomware campaigns are weakness-linked to techniques employed by LAPSUS$?",
        group_kev_cves("G1004", "v.known_ransomware_use = true"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    M(
        "Which KEV CVEs with a CVSS score of at least 9.0 have a weakness tied via CAPEC to techniques used by LAPSUS$?",
        group_kev_cves("G1004", "v.cvss_score >= 9.0"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    M(
        "Which critical KEV CVEs (CVSS 9.0 or higher) are weakness-linked via CAPEC to techniques used by Andariel?",
        group_kev_cves("G0138", "v.cvss_score >= 9.0"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    M(
        "Which ransomware-associated KEV CVEs have a weakness linked through CAPEC to techniques used by Cobalt Group?",
        group_kev_cves("G0080", "v.known_ransomware_use = true"),
        4,
        tags=_tags("kev", "chain", "filter"),
        notes=_CHAIN_NOTE,
    ),
    # CVE -> CWE -> CAPEC -> technique (3 hops)
    M("Which ATT&CK techniques are linked, via its weakness and CAPEC, to Spring4Shell (CVE-2022-22965)?", cve_techniques("CVE-2022-22965"), 3, tags=_tags("chain"), notes=_CHAIN_NOTE),
    M("Which techniques are associated through weakness and CAPEC with CVE-2024-3400?", cve_techniques("CVE-2024-3400"), 3, tags=_tags("chain"), notes=_CHAIN_NOTE),
    M("Which ATT&CK techniques relate via CAPEC to the weakness of CVE-2024-38112?", cve_techniques("CVE-2024-38112"), 3, tags=_tags("chain"), notes=_CHAIN_NOTE),
    # CWE -> CAPEC -> technique -> group (3 hops)
    M("Which groups use techniques that CAPEC patterns exploiting CWE-94 (Code Injection) map to?", cwe_groups("CWE-94"), 3, tags=_tags("chain")),
    M("Which groups use techniques related through CAPEC to the hard-coded credentials weakness CWE-798?", cwe_groups("CWE-798"), 3, tags=_tags("chain")),
    # AI techniques
    M(
        "Which mitigations apply to both Indirect Prompt Injection (T1698) and Direct Prompt Injection (T1699)?",
        "MATCH (m:Mitigation)-[:MITIGATES]->(:Technique {attack_id: 'T1698'}) "
        "MATCH (m)-[:MITIGATES]->(:Technique {attack_id: 'T1699'}) RETURN DISTINCT m.attack_id AS id ORDER BY id",
        2,
        tags=_tags(AI),
    ),
    M(
        "Which mitigations address the AI-related techniques that Kimsuky uses?",
        "MATCH (:Group {attack_id: 'G0094'})-[:USES]->(t:Technique) "
        "WHERE t.attack_id IN ['T1682', 'T1588.007', 'T1608.007', 'T1700'] "
        "MATCH (m:Mitigation)-[:MITIGATES]->(t) RETURN DISTINCT m.attack_id AS id ORDER BY id",
        2,
        tags=_tags(AI),
    ),
    M(
        "Which groups use both Query Public AI Services (T1682) and Spearphishing Attachment (T1566.001)?",
        "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T1682'}) "
        "MATCH (g)-[:USES]->(:Technique {attack_id: 'T1566.001'}) RETURN DISTINCT g.attack_id AS id ORDER BY id",
        2,
        tags=_tags(AI),
    ),
]

# ================================================================ aggregation (25)
def top_techniques_in_tactic(tactic: str) -> str:
    """Ranked-list Cypher: property maps are doubled because the builder runs str.format on it."""
    return (
        "MATCH (g:Group)-[:USES]->(t:Technique)-[:IN_TACTIC]->(:Tactic {{shortname: '" + tactic + "'}}) "
        "RETURN t.attack_id AS id, count(DISTINCT g) AS value ORDER BY value DESC, id LIMIT {limit}"
    )


AGGREGATION = [
    RANK(
        "Which 5 techniques are used by the most groups?",
        "MATCH (g:Group)-[:USES]->(t:Technique) RETURN t.attack_id AS id, count(DISTINCT g) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 5 groups use the most techniques?",
        "MATCH (g:Group)-[:USES]->(t:Technique) RETURN g.attack_id AS id, count(DISTINCT t) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 5 software entries are used by the most groups?",
        "MATCH (g:Group)-[:USES]->(s:Software) RETURN s.attack_id AS id, count(DISTINCT g) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 3 mitigations cover the most techniques?",
        "MATCH (m:Mitigation)-[:MITIGATES]->(t:Technique) RETURN m.attack_id AS id, count(DISTINCT t) AS value ORDER BY value DESC, id LIMIT {limit}",
        3,
        1,
    ),
    RANK(
        "Which 3 tactics contain the most techniques?",
        "MATCH (t:Technique)-[:IN_TACTIC]->(x:Tactic) RETURN x.attack_id AS id, count(DISTINCT t) AS value ORDER BY value DESC, id LIMIT {limit}",
        3,
        1,
    ),
    RANK(
        "Which 5 CWEs are exploited by the most CAPEC attack patterns?",
        "MATCH (c:CAPEC)-[:EXPLOITS]->(w:CWE) RETURN w.cwe_id AS id, count(DISTINCT c) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 5 weaknesses (CWEs) are associated with the most CISA KEV CVEs?",
        "MATCH (v:CVE {{kev: true}})-[:HAS_WEAKNESS]->(w:CWE) RETURN w.cwe_id AS id, count(DISTINCT v) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
        tags=_tags("kev"),
    ),
    RANK(
        "Which 4 CAPEC patterns map to the most ATT&CK techniques?",
        "MATCH (c:CAPEC)-[:MAPS_TO]->(t:Technique) RETURN c.capec_id AS id, count(DISTINCT t) AS value ORDER BY value DESC, id LIMIT {limit}",
        4,
        1,
    ),
    RANK(
        "Which 5 techniques are used by the most software entries?",
        "MATCH (s:Software)-[:USES]->(t:Technique) RETURN t.attack_id AS id, count(DISTINCT s) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 5 groups use the most software?",
        "MATCH (g:Group)-[:USES]->(s:Software) RETURN g.attack_id AS id, count(DISTINCT s) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 5 techniques have the most sub-techniques?",
        "MATCH (s:Technique)-[:SUBTECHNIQUE_OF]->(t:Technique) RETURN t.attack_id AS id, count(DISTINCT s) AS value ORDER BY value DESC, id LIMIT {limit}",
        5,
        1,
    ),
    RANK(
        "Which 3 initial access techniques are used by the most groups?",
        top_techniques_in_tactic("initial-access"),
        3,
        2,
    ),
    RANK(
        "Which 3 credential access techniques are used by the most groups?",
        top_techniques_in_tactic("credential-access"),
        3,
        2,
    ),
    COUNT("How many techniques does APT29 use?", "MATCH (:Group {attack_id: 'G0016'})-[:USES]->(t:Technique) RETURN count(DISTINCT t) AS value", 1),
    COUNT("How many sub-techniques does Command and Scripting Interpreter (T1059) have?", "MATCH (:Technique)-[:SUBTECHNIQUE_OF]->(:Technique {attack_id: 'T1059'}) RETURN count(*) AS value", 1),
    COUNT("How many groups use Spearphishing Attachment (T1566.001)?", "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T1566.001'}) RETURN count(DISTINCT g) AS value", 1),
    COUNT("How many mitigations are there in the knowledge graph?", "MATCH (m:Mitigation) RETURN count(m) AS value", 1),
    COUNT("How many CISA KEV CVEs are known to have been used in ransomware campaigns?", "MATCH (v:CVE {kev: true, known_ransomware_use: true}) RETURN count(v) AS value", 1, tags=_tags("kev")),
    COUNT("How many techniques belong to the Impact tactic?", "MATCH (t:Technique)-[:IN_TACTIC]->(:Tactic {shortname: 'impact'}) RETURN count(DISTINCT t) AS value", 1),
    COUNT("How many software entries use LSASS Memory credential dumping (T1003.001)?", "MATCH (s:Software)-[:USES]->(:Technique {attack_id: 'T1003.001'}) RETURN count(DISTINCT s) AS value", 1),
    COUNT("How many CAPEC attack patterns exploit CWE-79 (Cross-site Scripting)?", "MATCH (c:CAPEC)-[:EXPLOITS]->(:CWE {cwe_id: 'CWE-79'}) RETURN count(DISTINCT c) AS value", 1),
    COUNT("How many CISA KEV CVEs have the weakness CWE-79?", "MATCH (v:CVE {kev: true})-[:HAS_WEAKNESS]->(:CWE {cwe_id: 'CWE-79'}) RETURN count(DISTINCT v) AS value", 1, tags=_tags("kev")),
    COUNT("How many mitigations apply to Indirect Prompt Injection (T1698)?", "MATCH (:Mitigation)-[:MITIGATES]->(:Technique {attack_id: 'T1698'}) RETURN count(*) AS value", 1, tags=_tags(AI)),
    COUNT("How many CVEs were added to the CISA KEV catalog in 2025?", "MATCH (v:CVE {kev: true}) WHERE v.kev_date_added STARTS WITH '2025' RETURN count(v) AS value", 1, tags=_tags("kev")),
    COUNT(
        "How many groups use both Spearphishing Attachment (T1566.001) and PowerShell (T1059.001)?",
        "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T1566.001'}) MATCH (g)-[:USES]->(:Technique {attack_id: 'T1059.001'}) RETURN count(DISTINCT g) AS value",
        2,
    ),
]

# ================================================================ semantic / fuzzy (15)
SEMANTIC = [
    SEM("How do attackers abuse scheduled tasks to keep persistence on a system?", concepts_prefix("T1053")),
    SEM("Which technique involves pulling credentials out of the LSASS process memory?", concepts(["T1003.001"])),
    SEM("What do attackers do when they encrypt a victim's files and demand payment?", concepts(["T1486"])),
    SEM("How do adversaries run their code inside the memory space of another running process?", concepts_prefix("T1055")),
    SEM("Which technique covers attackers running commands through PowerShell?", concepts(["T1059.001"])),
    SEM("How do attackers trick users into clicking a malicious link in an email or message?", concepts(["T1566.002"])),
    SEM("Which technique is about stealing a user's web session cookies to hijack their login?", concepts(["T1539"])),
    SEM("What weakness lets an attacker alter a database query through unsanitized user input?", concepts(["CWE-89", "CAPEC-66"])),
    SEM("Which weaknesses cover writing data past the end of a memory buffer?", concepts(["CWE-787", "CWE-120", "CWE-121", "CWE-122"])),
    SEM("What kind of weakness lets an attacker run script in another user's browser?", concepts(["CWE-79", "CAPEC-63"])),
    SEM("Which weaknesses concern passwords that are built into software?", concepts(["CWE-798", "CWE-259"])),
    SEM("What weakness lets an attacker read files outside the intended directory?", concepts(["CWE-22", "CAPEC-126"])),
    SEM("How can an attacker manipulate an application built on a large language model through crafted input?", concepts(["T1698", "T1699"]), tags=_tags(AI)),
    SEM("Which techniques involve attackers using generative AI services during their operations?", concepts(["T1682", "T1588.007"]), tags=_tags(AI)),
    SEM("How do adversaries erase evidence of their activity from log files?", concepts_prefix("T1070")),
]

# ================================================================ unanswerable (10)
UNANSWERABLE = [
    NOANSWER(
        "What is the EPSS exploit-prediction score of CVE-2024-38112?",
        "MATCH (v:CVE {cve_id: 'CVE-2024-38112'}) WHERE v.epss IS NOT NULL RETURN v.cve_id AS id",
        precondition="MATCH (v:CVE {cve_id: 'CVE-2024-38112'}) RETURN v.cve_id AS id",
        notes="EPSS is not ingested.",
    ),
    NOANSWER(
        "Which Microsoft security update (KB article) fixes CVE-2024-38112?",
        "MATCH (v:CVE {cve_id: 'CVE-2024-38112'}) WHERE v.kb_article IS NOT NULL OR v.patch IS NOT NULL RETURN v.cve_id AS id",
        precondition="MATCH (v:CVE {cve_id: 'CVE-2024-38112'}) RETURN v.cve_id AS id",
        notes="Patch and advisory data are not ingested.",
    ),
    NOANSWER(
        "Which groups use the technique T9999?",
        "MATCH (g:Group)-[:USES]->(:Technique {attack_id: 'T9999'}) RETURN g.attack_id AS id",
        notes="T9999 does not exist.",
    ),
    NOANSWER(
        "Which CVEs are associated with CWE-99999?",
        "MATCH (v:CVE)-[:HAS_WEAKNESS]->(:CWE {cwe_id: 'CWE-99999'}) RETURN v.cve_id AS id",
        notes="CWE-99999 does not exist.",
    ),
    NOANSWER(
        "Which ICS techniques does Sandworm Team use?",
        "MATCH (t:Technique) WHERE t.attack_id =~ 'T0[0-9]{3}' RETURN t.attack_id AS id",
        precondition="MATCH (g:Group {attack_id: 'G0034'}) RETURN g.attack_id AS id",
        notes="Only the Enterprise matrix is ingested; ICS technique ids (T08xx) are absent.",
    ),
    NOANSWER(
        "Which Splunk detection rules cover PowerShell (T1059.001)?",
        "MATCH (r:DetectionRule) RETURN r.name AS id",
        precondition="MATCH (t:Technique {attack_id: 'T1059.001'}) RETURN t.attack_id AS id",
        notes="No detection-rule data in the graph.",
    ),
    NOANSWER(
        "What ransom amounts have been demanded using LockBit 3.0?",
        "MATCH (s:Software {name: 'LockBit 3.0'}) WHERE s.ransom_amount IS NOT NULL RETURN s.attack_id AS id",
        precondition="MATCH (s:Software {name: 'LockBit 3.0'}) RETURN s.attack_id AS id",
        notes="Financial impact is not modelled.",
    ),
    NOANSWER(
        "Who developed the Cobalt Strike software?",
        "MATCH (s:Software {name: 'Cobalt Strike'}) WHERE s.author IS NOT NULL OR s.developer IS NOT NULL RETURN s.attack_id AS id",
        precondition="MATCH (s:Software {name: 'Cobalt Strike'}) RETURN s.attack_id AS id",
        notes="Authorship is not modelled.",
    ),
    NOANSWER(
        "Which CVEs does the Direct Prompt Injection technique (T1699) map to?",
        "MATCH (:Technique {attack_id: 'T1699'})<-[:MAPS_TO]-(:CAPEC)-[:EXPLOITS]->(:CWE)<-[:HAS_WEAKNESS]-(v:CVE) RETURN v.cve_id AS id",
        precondition="MATCH (t:Technique {attack_id: 'T1699'}) RETURN t.attack_id AS id",
        tags=_tags(AI),
        notes="T1699 has no CAPEC mapping, so no CVE can be reached.",
    ),
    NOANSWER(
        "What is the CVSS base score of CVE-2099-0001?",
        "MATCH (v:CVE {cve_id: 'CVE-2099-0001'}) RETURN v.cvss_score AS id",
        notes="That CVE id does not exist.",
    ),
]

SPECS: list[QuestionSpec] = [*SINGLE_HOP, *MULTI_HOP, *AGGREGATION, *SEMANTIC, *UNANSWERABLE]
