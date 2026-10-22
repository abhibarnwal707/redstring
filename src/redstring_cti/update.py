"""`make update`: refresh the graph from the sources without a full reload.

1. download: conditional and idempotent, so only changed files are fetched;
2. NVD: re-read only the `modified` feed (CVEs added or changed since the yearly files), and delete any CVE that
   NVD now marks Rejected (the full loader skips them but would never remove one already in the graph);
3. KEV: re-sync the actively-exploited flags;
4. ATT&CK / CWE / CAPEC: if their raw files changed, say so and stop short of reloading. They are version-pinned and
   the gold set and evaluation depend on them, so a version change is a deliberate `make load`;
5. embeddings: incremental (only nodes missing a vector or whose text changed).
Reports ingested by `make ingest-report` are never touched."""

import argparse
import json
import logging
import subprocess
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from neo4j import Driver

from redstring_cti.config import PROCESSED_DIR, RAW_DIR
from redstring_cti.ingest.download import load_manifest

log = logging.getLogger(__name__)
LOG_PATH = PROCESSED_DIR / "update_log.jsonl"
PINNED_SOURCES = ("attack", "cwe", "capec")  # manifest keys whose change needs a deliberate reload


def rejected_in(feed: Path) -> set[str]:
    """CVE ids that this NVD feed marks Rejected."""
    from redstring_cti.ingest.nvd import iter_cves

    rejected: set[str] = set()
    for _ in iter_cves(feed, Counter(), rejected):
        pass
    return rejected


def delete_cves(driver: Driver, ids: set[str], batch: int = 1000) -> int:
    """Remove CVE nodes (and their edges). Only exact ids from `ids` are touched."""
    removed = 0
    ordered = sorted(ids)
    for i in range(0, len(ordered), batch):
        summary = driver.execute_query("MATCH (v:CVE) WHERE v.cve_id IN $ids DETACH DELETE v", ids=ordered[i : i + batch]).summary
        removed += summary.counters.nodes_deleted
    return removed


def manifest_hashes() -> dict[str, str]:
    return {name: entry.sha256 for name, entry in load_manifest(RAW_DIR).items()}


def changed_files(before: dict[str, str], after: dict[str, str]) -> list[str]:
    return sorted(name for name in after if before.get(name) != after[name])


def pinned_changes(changed: list[str]) -> list[str]:
    return [name for name in changed if name.startswith(PINNED_SOURCES)]


def run_update(driver: Driver, *, download: bool = True, embed: bool = True, dry_run: bool = False) -> dict[str, Any]:
    from redstring_cti.graph.embeddings import build_embeddings
    from redstring_cti.graph.loader import graph_counts
    from redstring_cti.ingest.kev import parse_kev, sync_kev
    from redstring_cti.ingest.nvd import feed_paths, load_nvd

    before_hashes = manifest_hashes()
    if download:
        subprocess.run([sys.executable, "-m", "redstring_cti.ingest.download"], check=True)
    changed = changed_files(before_hashes, manifest_hashes())
    report: dict[str, Any] = {"at": datetime.now(UTC).isoformat(timespec="seconds"), "changed_files": changed, "dry_run": dry_run}
    if pinned := pinned_changes(changed):
        report["needs_full_reload"] = pinned
        log.warning("version-pinned sources changed (%s): run `make load`, then `make embed`, rebuild the gold set and re-run the baselines", ", ".join(pinned))

    modified = next((p for p in feed_paths(RAW_DIR) if p.name.startswith("nvdcve-2.0-modified")), None)
    before = graph_counts(driver)["nodes"].get("CVE", 0)
    if modified is not None:
        rejected = rejected_in(modified)
        present = {r["id"] for r in driver.execute_query("MATCH (v:CVE) WHERE v.cve_id IN $ids RETURN v.cve_id AS id", ids=sorted(rejected)).records} if rejected else set()
        report["rejected_in_modified_feed"] = len(rejected)
        report["rejected_present_in_graph"] = len(present)
        if not dry_run:
            result = load_nvd(driver, [modified])
            report["nvd_modified"] = result.stats
            report["cves_deleted"] = delete_cves(driver, present)
            sync_kev(driver, parse_kev(RAW_DIR / "known_exploited_vulnerabilities.json"))
            if embed:
                report["embeddings"] = build_embeddings(driver)
    report["cve_nodes_before"] = before
    report["cve_nodes_after"] = graph_counts(driver)["nodes"].get("CVE", 0)
    if not dry_run:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a") as f:
            f.write(json.dumps(report) + "\n")
    return report


def main() -> None:
    from redstring_cti.graph.loader import get_driver

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--no-embed", action="store_true")
    ap.add_argument("--dry-run", action="store_true", help="report what would change; write nothing")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    driver = get_driver()
    try:
        print(json.dumps(run_update(driver, download=not args.no_download, embed=not args.no_embed, dry_run=args.dry_run), indent=1))
    finally:
        driver.close()


if __name__ == "__main__":
    main()
