"""CISA Known Exploited Vulnerabilities: flag matching CVE nodes with kev = true."""

import logging
from pathlib import Path

import orjson
from neo4j import Driver, ManagedTransaction
from pydantic import BaseModel

from redstring_cti.ingest.common import batched

log = logging.getLogger(__name__)

BATCH_SIZE = 1000
_MARK = """
UNWIND $rows AS row
MATCH (c:CVE {cve_id: row.cve_id})
SET c.kev = true, c.kev_date_added = row.date_added, c.kev_due_date = row.due_date,
    c.known_ransomware_use = row.ransomware
RETURN count(c) AS matched
"""


class KevEntry(BaseModel):
    cve_id: str
    date_added: str | None = None
    due_date: str | None = None
    ransomware: bool = False


def parse_kev(path: Path) -> list[KevEntry]:
    data = orjson.loads(path.read_bytes())
    return [
        KevEntry(
            cve_id=v["cveID"],
            date_added=v.get("dateAdded"),
            due_date=v.get("dueDate"),
            ransomware=v.get("knownRansomwareCampaignUse") == "Known",
        )
        for v in data["vulnerabilities"]
    ]


def load_kev(driver: Driver, entries: list[KevEntry]) -> dict[str, int]:
    """Additive: flag the CVE nodes that exist and report how many entries had no node."""

    def mark(tx: ManagedTransaction, rows: list[dict[str, object]]) -> int:
        return int(tx.run(_MARK, rows=rows).single()["matched"])  # type: ignore[index]

    matched = 0
    with driver.session() as session:
        for batch in batched(entries, BATCH_SIZE):
            matched += session.execute_write(mark, [e.model_dump() for e in batch])
    return {"kev_entries": len(entries), "kev_matched": matched, "kev_unmatched": len(entries) - matched}


def sync_kev(driver: Driver, entries: list[KevEntry]) -> dict[str, int]:
    """Full rebuild semantics: clear old flags, apply the catalog, default the rest to false."""
    with driver.session() as session:
        session.run(
            "MATCH (c:CVE {kev: true}) SET c.kev = false, c.kev_date_added = null, "
            "c.kev_due_date = null, c.known_ransomware_use = null"
        ).consume()
    result = load_kev(driver, entries)
    with driver.session() as session:
        session.run("MATCH (c:CVE) WHERE c.kev IS NULL SET c.kev = false").consume()
    log.info("kev: %s", result)
    return result
