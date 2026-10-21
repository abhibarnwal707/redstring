import gzip
from collections import Counter
from pathlib import Path
from typing import Any

import orjson
import pytest
from neo4j import Driver

from redstring_cti.config import RAW_DIR
from redstring_cti.graph.loader import apply_schema
from redstring_cti.ingest.cwe import load_cwe, parse_cwe
from redstring_cti.ingest.kev import load_kev, parse_kev
from redstring_cti.ingest.nvd import feed_paths, iter_cves, load_nvd

FIXTURES = Path(__file__).parent / "fixtures"


def _metric(version: str, score: float, kind: str = "Primary", sev: str = "HIGH") -> dict[str, Any]:
    return {"type": kind, "cvssData": {"version": version, "baseScore": score, "baseSeverity": sev}}


def _cve(cve_id: str, status: str = "Analyzed", **kw: Any) -> dict[str, Any]:
    cve: dict[str, Any] = {
        "id": cve_id,
        "vulnStatus": status,
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-02-01T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "hola"}, {"lang": "en", "value": "  An  English\ndescription. "}],
    }
    cve.update(kw)
    return {"cve": cve}


def _weak(kind: str, *values: str) -> dict[str, Any]:
    return {"type": kind, "description": [{"lang": "en", "value": v} for v in values]}


@pytest.fixture
def feed(tmp_path: Path) -> Path:
    vulns = [
        _cve(  # Primary beats Secondary; real CWEs kept, pseudo-CWE filtered, unknown CWE kept at parse time
            "CVE-TEST-1",
            metrics={
                "cvssMetricV31": [_metric("3.1", 6.0, "Secondary", "MEDIUM"), _metric("3.1", 9.8, "Primary", "CRITICAL")],
                "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}],
            },
            weaknesses=[_weak("Primary", "CWE-TEST-1"), _weak("Secondary", "CWE-TEST-2", "NVD-CWE-Other", "CWE-TEST-404")],
        ),
        _cve("CVE-TEST-2", status="Rejected"),
        _cve(  # old CVE: only CVSS v2, severity sits outside cvssData
            "CVE-TEST-3",
            metrics={"cvssMetricV2": [{"type": "Primary", "cvssData": {"version": "2.0", "baseScore": 7.5}, "baseSeverity": "HIGH"}]},
            weaknesses=[_weak("Primary", "NVD-CWE-noinfo")],
        ),
        _cve(  # 4.0 is preferred over 3.0
            "CVE-TEST-4",
            metrics={"cvssMetricV30": [_metric("3.0", 5.0)], "cvssMetricV40": [_metric("4.0", 8.7, "Secondary")]},
        ),
        _cve("CVE-TEST-5", status="Deferred"),
    ]
    path = tmp_path / "nvdcve-2.0-2099.json.gz"
    path.write_bytes(gzip.compress(orjson.dumps({"format": "NVD_CVE", "vulnerabilities": vulns})))
    return path


def test_iter_cves_fixture(feed: Path) -> None:
    stats: Counter[str] = Counter()
    recs = {r.node.key: r for r in iter_cves(feed, stats)}
    assert set(recs) == {"CVE-TEST-1", "CVE-TEST-3", "CVE-TEST-4", "CVE-TEST-5"}  # rejected skipped
    assert stats["cves_seen"] == 5 and stats["skipped_rejected:CVE"] == 1

    one = recs["CVE-TEST-1"]
    assert one.node.props["description"] == "An English description."
    assert (one.node.props["cvss_score"], one.node.props["cvss_severity"]) == (9.8, "CRITICAL")
    assert one.node.props["cvss_v31_score"] == 9.8 and one.node.props["cvss_version"] == "3.1"
    assert one.weaknesses == {"CWE-TEST-1": "Primary", "CWE-TEST-2": "Secondary", "CWE-TEST-404": "Secondary"}

    old = recs["CVE-TEST-3"].node.props
    assert (old["cvss_score"], old["cvss_severity"], old["cvss_version"]) == (7.5, "HIGH", "2.0")
    assert "cvss_v31_score" not in old and recs["CVE-TEST-3"].weaknesses == {}

    assert recs["CVE-TEST-4"].node.props["cvss_version"] == "4.0"
    assert "cvss_score" not in recs["CVE-TEST-5"].node.props
    assert stats["weakness_pseudo_filtered"] == 2
    assert stats["cves_with_cwe"] == 1 and stats["cves_without_cwe"] == 3 and stats["cves_without_cvss"] == 1


def test_feed_paths_orders_modified_last(tmp_path: Path) -> None:
    for name in ("nvdcve-2.0-2010.json.gz", "nvdcve-2.0-modified.json.gz", "nvdcve-2.0-2002.json.gz", "x.json.gz"):
        (tmp_path / name).touch()
    assert [p.name for p in feed_paths(tmp_path)] == [
        "nvdcve-2.0-2002.json.gz",
        "nvdcve-2.0-2010.json.gz",
        "nvdcve-2.0-modified.json.gz",
    ]


def test_parse_kev(tmp_path: Path) -> None:
    path = tmp_path / "kev.json"
    path.write_bytes(
        orjson.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-TEST-1", "dateAdded": "2024-03-01", "dueDate": "2024-03-22", "knownRansomwareCampaignUse": "Known"},
                    {"cveID": "CVE-TEST-404", "dateAdded": "2024-03-02", "knownRansomwareCampaignUse": "Unknown"},
                ]
            }
        )
    )
    a, b = parse_kev(path)
    assert (a.cve_id, a.ransomware, a.due_date) == ("CVE-TEST-1", True, "2024-03-22")
    assert b.ransomware is False


def test_load_nvd_and_kev_idempotent(driver: Driver, isolated_test_graph: None, feed: Path, tmp_path: Path) -> None:
    apply_schema(driver)
    kev_path = tmp_path / "kev.json"
    kev_path.write_bytes(
        orjson.dumps(
            {
                "vulnerabilities": [
                    {"cveID": "CVE-TEST-1", "dateAdded": "2024-03-01", "dueDate": "2024-03-22", "knownRansomwareCampaignUse": "Known"},
                    {"cveID": "CVE-TEST-404", "dateAdded": "2024-03-02", "knownRansomwareCampaignUse": "Unknown"},
                ]
            }
        )
    )

    def load_all() -> tuple[Any, dict[str, int]]:
        load_cwe(driver, parse_cwe(FIXTURES / "cwe_mini.xml"))
        result = load_nvd(driver, [feed], version="test", batch_size=2)  # several batches
        return result, load_kev(driver, parse_kev(kev_path))

    def snapshot() -> tuple[int, int]:
        with driver.session() as session:
            n = session.run("MATCH (n {source_version: 'test'}) RETURN count(n) AS c").single()
            e = session.run("MATCH (a {source_version: 'test'})-[r]->() RETURN count(r) AS c").single()
        assert n and e
        return n["c"], e["c"]

    result, kev = load_all()
    first = snapshot()
    load_all()
    assert snapshot() == first == (6, 3)  # 2 CWE + 4 CVE nodes; CHILD_OF + 2 HAS_WEAKNESS
    assert result.stats["edges:HAS_WEAKNESS"] == 2
    assert result.unmatched_cwe == {"CWE-TEST-404": 1}
    assert kev == {"kev_entries": 2, "kev_matched": 1, "kev_unmatched": 1}

    with driver.session() as session:
        row = session.run(
            """MATCH (c:CVE {cve_id: 'CVE-TEST-1'})-[h:HAS_WEAKNESS]->(w:CWE)
               RETURN c.kev AS kev, c.known_ransomware_use AS rw, c.kev_date_added AS d, c.uid AS uid,
                      collect(w.cwe_id + ':' + h.type) AS ws"""
        ).single()
    assert row and row["kev"] is True and row["rw"] is True and row["d"] == "2024-03-01"
    assert row["uid"] == "CVE:CVE-TEST-1" and sorted(row["ws"]) == ["CWE-TEST-1:Primary", "CWE-TEST-2:Secondary"]


@pytest.mark.skipif(not (RAW_DIR / "nvdcve-2.0-2004.json.gz").exists(), reason="run `make download` first")
def test_iter_real_feed_2004() -> None:
    stats: Counter[str] = Counter()
    recs = list(iter_cves(RAW_DIR / "nvdcve-2.0-2004.json.gz", stats))
    assert stats["cves_seen"] == len(recs) + stats["skipped_rejected:CVE"]
    assert len({r.node.key for r in recs}) == len(recs)
    assert all(r.node.key.startswith("CVE-") for r in recs)
