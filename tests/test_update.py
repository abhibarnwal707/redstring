import gzip
from pathlib import Path

import orjson
from neo4j import Driver

from redstring_cti import update


def write_feed(path: Path, cves: list[dict[str, object]]) -> Path:
    path.write_bytes(gzip.compress(orjson.dumps({"vulnerabilities": [{"cve": c} for c in cves]})))
    return path


def cve(cid: str, status: str = "Analyzed") -> dict[str, object]:
    return {"id": cid, "vulnStatus": status, "descriptions": [{"lang": "en", "value": "d"}], "published": "2026-01-01T00:00:00.000", "lastModified": "2026-01-02T00:00:00.000", "weaknesses": [], "metrics": {}}


def test_rejected_ids_are_found_in_a_feed(tmp_path: Path) -> None:
    feed = write_feed(tmp_path / "f.json.gz", [cve("CVE-2099-0001"), cve("CVE-2099-0002", "Rejected"), cve("CVE-2099-0003", "Rejected")])
    assert update.rejected_in(feed) == {"CVE-2099-0002", "CVE-2099-0003"}


def test_delete_cves_removes_only_the_named_nodes(driver: Driver, isolated_test_graph: None) -> None:
    keep, drop = "CVE-2099-TEST-1", "CVE-2099-TEST-2"
    driver.execute_query("UNWIND $ids AS i MERGE (v:CVE {cve_id: i}) SET v.source_version = 'test', v.uid = 'CVE:' + i", ids=[keep, drop])
    assert update.delete_cves(driver, {drop, "CVE-2099-TEST-NOT-THERE"}) == 1
    rows, _, _ = driver.execute_query("MATCH (v:CVE) WHERE v.cve_id IN [$a, $b] RETURN v.cve_id AS id", a=keep, b=drop)
    assert [r["id"] for r in rows] == [keep]
    assert update.delete_cves(driver, set()) == 0


def test_changed_files_and_pinned_detection() -> None:
    before = {"attack": "a", "nvd-2025": "x", "kev": "k"}
    after = {"attack": "b", "nvd-2025": "x", "kev": "k2", "nvd-modified": "m"}
    changed = update.changed_files(before, after)
    assert changed == ["attack", "kev", "nvd-modified"]
    assert update.pinned_changes(changed) == ["attack"] and update.pinned_changes(["kev", "nvd-2025"]) == []


def test_dry_run_changes_nothing(driver: Driver) -> None:
    before, _, _ = driver.execute_query("MATCH (v:CVE) RETURN count(v) AS n")
    report = update.run_update(driver, download=False, embed=False, dry_run=True)
    after, _, _ = driver.execute_query("MATCH (v:CVE) RETURN count(v) AS n")
    assert report["dry_run"] is True and before[0]["n"] == after[0]["n"] == report["cve_nodes_before"]
