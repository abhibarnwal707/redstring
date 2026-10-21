from typing import Any

import pytest
from neo4j import Driver

from redstring_cti.graph.dq import fraction, graph_metrics, pct, render, table


def test_formatting_helpers() -> None:
    assert pct(1, 4) == "25.0%" and pct(1, 0) == "n/a"
    assert fraction(179, 706) == "179 of 706 (25.4%)"
    assert table(["a", "b"], [["x", 1234]]).splitlines()[2] == "| x | 1,234 |"


def _metrics() -> dict[str, Any]:
    return {
        "graph": {
            "nodes": {"CVE": 10, "Technique": 4},
            "edges": {"HAS_WEAKNESS": 7},
            "orphans": {"CVE": 3, "Technique": 0},
            "tech": {"total": 4, "mapped": 1, "subs": 2, "subs_mapped": 0},
            "capec": {"total": 5, "to_technique": 2, "to_cwe": 4},
            "cve": {"total": 10, "with_cwe": 7, "kev": 2, "kev_with_cwe": 1, "on_chain": 3, "kev_on_chain": 1, "no_cvss": 1},
            "cvss_versions": {"3.1": 9, "None": 1},
            "groups": {"total": 3, "with_technique": 3, "to_capec": 2, "to_cwe": 2, "to_cve": 1, "to_kev": 1},
            "uses_edges": {"total": 8, "to_mapped_technique": 2},
            "chain_by_abstraction": {"Class": 2, "Base": 1},
            "top_chain_cwes": [{"cwe": "CWE-20", "name": "Improper Input Validation", "abstraction": "Class", "cves": 2}],
            "embeddings": {"CVE": (3, 10), "Technique": (4, 4)},
            "apt29": {"techniques": 6, "with_capec": 2},
        },
        "source": {
            "attack_skips": {"skipped_revoked:attack-pattern": 5},
            "cwe_version": "9.9",
            "cwe_skips": {},
            "capec_version": "1.1",
            "capec_skips": {"skipped_deprecated:Attack_Pattern": 2},
            "maps_to_parsed": 6,
            "maps_to_dropped": 1,
            "nvd": {
                "feeds": 2, "records": 11, "distinct_live": 10, "distinct_rejected": 1,
                "classes": {"matched": 7, "pseudo_only": 2, "no_weakness_data": 1},
                "unmatched_distinct": 0, "unmatched_refs": 0, "unmatched_top": [],
            },
            "kev": {"version": "v", "count": 2},
            "nvd_timestamp": "2026-01-01T00:00:00",
        },
    }


def test_render_contains_every_section_and_the_numbers() -> None:
    text = render(_metrics())
    for heading in ("## 1.", "## 2.", "## 3.", "## 4.", "## 5.", "## 6.", "## 7."):
        assert heading in text
    assert "1 of 4 (25.0%)" in text  # technique coverage
    assert "| CVE | 3 | 10 |" in text  # orphans
    assert "mappings dropped" in text and "| 1 |" in text
    assert "only that share of techniques" in text


def test_graph_metrics_are_internally_consistent(driver: Driver) -> None:
    g = graph_metrics(driver)
    if not g["nodes"].get("Technique"):
        pytest.skip("graph not loaded (make load)")
    assert g["cve"]["with_cwe"] + g["orphans"]["CVE"] == g["cve"]["total"]  # CVE's only edge type is HAS_WEAKNESS
    assert g["tech"]["subs_mapped"] <= g["tech"]["mapped"] <= g["tech"]["total"]
    assert g["groups"]["to_kev"] <= g["groups"]["to_cve"] <= g["groups"]["to_cwe"] <= g["groups"]["to_capec"]
    assert g["cve"]["kev_on_chain"] <= g["cve"]["on_chain"] <= g["cve"]["with_cwe"]
    assert g["nodes"]["CVE"] == g["cve"]["total"] and g["edges"]["HAS_WEAKNESS"] >= g["cve"]["with_cwe"]
