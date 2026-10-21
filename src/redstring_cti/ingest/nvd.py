"""NVD (CVE JSON 2.0 yearly feeds) ingester.

Feeds are streamed with ijson so a 300 MB year never sits in memory. `iter_cves` is pure
(file -> records + statistics); `load_nvd` writes CVE nodes and HAS_WEAKNESS edges.
"""

import gzip
import logging
import re
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import ijson
from neo4j import Driver
from pydantic import BaseModel

from redstring_cti.graph.loader import existing_keys, write_edges, write_nodes
from redstring_cti.ingest.common import Edge, Node, batched, clean_text

log = logging.getLogger(__name__)

SOURCE = "nvd"
KEY_PROP = "cve_id"
BATCH_SIZE = 5000
SKIP_STATUS = {"Rejected"}
# Best available CVSS wins; v2.0 only for old CVEs that have nothing newer.
CVSS_PREFERENCE = (
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)
_FEED_NAME = re.compile(r"nvdcve-2\.0-(\w+)\.json\.gz")


class CveRecord(BaseModel):
    node: Node
    weaknesses: dict[str, str]  # CWE id -> "Primary" | "Secondary"


def feed_paths(raw_dir: Path) -> list[Path]:
    """Yearly feeds in ascending order, then the `modified` feed last so it wins on overlap."""
    paths = [p for p in raw_dir.glob("nvdcve-2.0-*.json.gz") if _FEED_NAME.fullmatch(p.name)]

    def order(p: Path) -> tuple[int, str]:
        label = _FEED_NAME.fullmatch(p.name).group(1)  # type: ignore[union-attr]
        return (1, label) if label == "modified" else (0, label)

    return sorted(paths, key=order)


def feed_label(path: Path) -> str:
    m = _FEED_NAME.fullmatch(path.name)
    return f"feed-{m.group(1)}" if m else path.name


def _pick_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for key, version in CVSS_PREFERENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        best = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = best.get("cvssData", {})
        score = data.get("baseScore")
        if score is None:
            continue
        severity = data.get("baseSeverity") or best.get("baseSeverity")  # v2 keeps it outside cvssData
        out: dict[str, Any] = {"cvss_score": score, "cvss_severity": severity, "cvss_version": version}
        if version == "3.1":
            out["cvss_v31_score"] = score
        return out
    return {}


def _english(descriptions: list[dict[str, Any]]) -> str | None:
    for d in descriptions:
        if d.get("lang") == "en":
            return clean_text(d.get("value"))
    return clean_text(descriptions[0].get("value")) if descriptions else None


def _weaknesses(cve: dict[str, Any], stats: Counter[str]) -> dict[str, str]:
    found: dict[str, str] = {}
    for w in cve.get("weaknesses", []):
        kind = w.get("type", "Secondary")
        for d in w.get("description", []):
            value = d.get("value", "")
            if not value.startswith("CWE-"):  # NVD-CWE-Other / NVD-CWE-noinfo are not real weaknesses
                stats["weakness_pseudo_filtered"] += 1
                continue
            if found.get(value) != "Primary":
                found[value] = kind
    return found


def iter_cves(path: Path, stats: Counter[str]) -> Iterator[CveRecord]:
    with gzip.open(path, "rb") as f:
        for item in ijson.items(f, "vulnerabilities.item", use_float=True):
            cve = item["cve"]
            stats["cves_seen"] += 1
            status = cve.get("vulnStatus")
            if status in SKIP_STATUS:
                stats[f"skipped_{status.lower()}:CVE"] += 1
                continue
            props: dict[str, Any] = {
                "description": _english(cve.get("descriptions", [])),
                "published": cve.get("published"),
                "last_modified": cve.get("lastModified"),
                "vuln_status": status,
                **_pick_cvss(cve.get("metrics", {})),
            }
            weaknesses = _weaknesses(cve, stats)
            stats["cves_with_cwe" if weaknesses else "cves_without_cwe"] += 1
            if "cvss_score" not in props:
                stats["cves_without_cvss"] += 1
            yield CveRecord(
                node=Node(
                    label="CVE",
                    key_prop=KEY_PROP,
                    key=cve["id"],
                    props={k: v for k, v in props.items() if v is not None},
                ),
                weaknesses=weaknesses,
            )


class NvdLoadResult(BaseModel):
    stats: dict[str, int]
    unmatched_cwe: dict[str, int]  # CWE ids referenced by CVEs but absent from the graph


def load_nvd(
    driver: Driver, paths: list[Path], *, version: str | None = None, batch_size: int = BATCH_SIZE
) -> NvdLoadResult:
    """Load CVE nodes and HAS_WEAKNESS edges. Load CWE first. `version` overrides the
    per-feed source_version (used by tests)."""
    cwe_ids = existing_keys(driver, "CWE", "cwe_id")
    totals: Counter[str] = Counter()
    unmatched: Counter[str] = Counter()
    for path in paths:
        stats: Counter[str] = Counter()
        label = version or feed_label(path)
        for batch in batched(iter_cves(path, stats), batch_size):
            write_nodes(driver, [r.node for r in batch], source=SOURCE, version=label, quiet=True)
            edges: list[Edge] = []
            for r in batch:
                for cwe, kind in r.weaknesses.items():
                    if cwe not in cwe_ids:
                        unmatched[cwe] += 1
                        continue
                    edges.append(
                        Edge(
                            rel="HAS_WEAKNESS",
                            src_label="CVE",
                            src_prop=KEY_PROP,
                            src_key=r.node.key,
                            dst_label="CWE",
                            dst_prop="cwe_id",
                            dst_key=cwe,
                            props={"type": kind},
                        )
                    )
            written = write_edges(driver, edges, source=SOURCE, quiet=True)
            stats["edges:HAS_WEAKNESS"] += written.get("HAS_WEAKNESS", 0)
        log.info("%s: %s", path.name, dict(sorted(stats.items())))
        totals.update(stats)
    stats_out = dict(sorted(totals.items()))
    stats_out["unmatched_cwe_references"] = sum(unmatched.values())
    stats_out["unmatched_cwe_distinct"] = len(unmatched)
    return NvdLoadResult(stats=stats_out, unmatched_cwe=dict(unmatched.most_common()))
