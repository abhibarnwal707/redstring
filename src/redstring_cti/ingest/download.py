"""Download all raw sources into data/raw and keep MANIFEST.json up to date.

Idempotent: a second run downloads nothing new. NVD feeds are skipped when the
upstream .meta SHA-256 matches the local file; other sources use conditional GETs
and a content hash comparison.
"""

import asyncio
import gzip
import hashlib
import logging
import re
import zlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import orjson
from pydantic import BaseModel

from redstring_cti.config import ATTACK_VERSION, NVD_START_YEAR, RAW_DIR

log = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json"
)
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0"

NVD_CONCURRENCY = 4  # measured: aggregate throughput scales with parallel connections
MAX_ATTEMPTS = 5
CHUNK_BYTES = 1 << 20  # NVD feeds are fetched in ranged 1 MiB chunks so a stall costs one chunk
CHUNK_TIMEOUT = httpx.Timeout(20.0, read=30.0)
MAX_CHUNK_ATTEMPTS = 12
MANIFEST_NAME = "MANIFEST.json"


class Source(BaseModel):
    name: str
    url: str
    filename: str
    version: str
    meta_url: str | None = None  # NVD: upstream .meta carrying the gz SHA-256


class ManifestEntry(BaseModel):
    source: str
    url: str
    filename: str
    version: str
    sha256: str
    size_bytes: int
    downloaded_at: str
    etag: str | None = None
    last_modified: str | None = None
    upstream_sha256: str | None = None  # NVD: SHA-256 of the uncompressed JSON, as in the .meta file


def build_sources(today: datetime | None = None) -> list[Source]:
    year_now = (today or datetime.now(UTC)).year
    sources = [
        Source(name="attack", url=ATTACK_URL, filename=f"enterprise-attack-{ATTACK_VERSION}.json", version=ATTACK_VERSION),
        Source(name="cwe", url=CWE_URL, filename="cwec_latest.xml.zip", version="latest"),
        Source(name="capec", url=CAPEC_URL, filename="capec_latest.xml", version="latest"),
        Source(name="kev", url=KEV_URL, filename="known_exploited_vulnerabilities.json", version="latest"),
    ]
    for year in [*range(NVD_START_YEAR, year_now + 1), "modified"]:
        stem = f"nvdcve-2.0-{year}"
        sources.append(
            Source(
                name=f"nvd-{year}",
                url=f"{NVD_BASE}/{stem}.json.gz",
                filename=f"{stem}.json.gz",
                version=str(year),
                meta_url=f"{NVD_BASE}/{stem}.meta",
            )
        )
    return sources


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def gunzip_sha256(path: Path) -> str | None:
    """SHA-256 of the decompressed stream; None if the gzip is truncated or corrupt."""
    h = hashlib.sha256()
    try:
        with gzip.open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except (OSError, EOFError, zlib.error):
        return None
    return h.hexdigest()


def load_manifest(raw_dir: Path) -> dict[str, ManifestEntry]:
    path = raw_dir / MANIFEST_NAME
    if not path.exists():
        return {}
    data = orjson.loads(path.read_bytes())
    return {k: ManifestEntry.model_validate(v) for k, v in data.items()}


def save_manifest(raw_dir: Path, manifest: dict[str, ManifestEntry]) -> None:
    payload = {k: v.model_dump() for k, v in sorted(manifest.items())}
    tmp = raw_dir / f"{MANIFEST_NAME}.tmp"
    tmp.write_bytes(orjson.dumps(payload, option=orjson.OPT_INDENT_2))
    tmp.replace(raw_dir / MANIFEST_NAME)


async def _with_retries(coro_fn, what: str):  # type: ignore[no-untyped-def]
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            return await coro_fn()
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            if attempt == MAX_ATTEMPTS:
                raise
            delay = 2**attempt
            log.warning("%s failed (%s), retry %d/%d in %ds", what, exc, attempt, MAX_ATTEMPTS, delay)
            await asyncio.sleep(delay)


async def _upstream_nvd_sha(client: httpx.AsyncClient, meta_url: str) -> str | None:
    async def fetch() -> str | None:
        resp = await client.get(meta_url)
        resp.raise_for_status()
        m = re.search(r"^sha256:([0-9A-Fa-f]{64})", resp.text, re.MULTILINE)
        return m.group(1).lower() if m else None

    return await _with_retries(fetch, f"meta {meta_url}")


def _conditional_headers(prior: ManifestEntry | None, dest: Path) -> dict[str, str]:
    headers: dict[str, str] = {}
    if prior and dest.exists():
        if prior.etag:
            headers["If-None-Match"] = prior.etag
        if prior.last_modified:
            headers["If-Modified-Since"] = prior.last_modified
    return headers


async def _download_oneshot(
    client: httpx.AsyncClient, src: Source, dest: Path, prior: ManifestEntry | None
) -> tuple[Path, httpx.Headers] | None:
    """Stream a small source into a fresh temp file. None means 304 Not Modified."""
    headers = _conditional_headers(prior, dest)
    tmp = dest.with_name(dest.name + ".part")

    async def fetch() -> tuple[Path, httpx.Headers] | None:
        async with client.stream("GET", src.url, headers=headers) as resp:
            if resp.status_code == 304:
                return None
            resp.raise_for_status()
            with tmp.open("wb") as f:
                async for chunk in resp.aiter_bytes(1 << 20):
                    f.write(chunk)
            return tmp, resp.headers

    return await _with_retries(fetch, f"download {src.name}")


async def _download_ranged(
    client: httpx.AsyncClient, src: Source, dest: Path, prior: ManifestEntry | None
) -> tuple[Path, httpx.Headers] | None:
    """Fetch in ranged chunks, resuming from an existing .part file.

    Each chunk has its own short timeout and retry, so a stalled connection costs
    one chunk rather than the whole file. None means 304 Not Modified.
    """
    tmp = dest.with_name(dest.name + ".part")
    have = tmp.stat().st_size if tmp.exists() else 0
    cond = _conditional_headers(prior, dest)
    total: int | None = None
    headers: httpx.Headers = httpx.Headers()
    failures = 0

    while total is None or have < total:
        req = {"Range": f"bytes={have}-{have + CHUNK_BYTES - 1}"}
        if have == 0:
            req.update(cond)
        try:
            resp = await client.get(src.url, headers=req, timeout=CHUNK_TIMEOUT)
            if resp.status_code in (429, 500, 502, 503, 504):
                resp.raise_for_status()
        except (httpx.TransportError, httpx.HTTPStatusError) as exc:
            failures += 1
            if failures > MAX_CHUNK_ATTEMPTS:
                raise
            delay = min(2**failures, 10)
            log.warning("%s @%d MiB: %r, retry %d in %ds", src.name, have >> 20, exc, failures, delay)
            await asyncio.sleep(delay)
            continue

        if resp.status_code == 304:
            return None
        if resp.status_code == 416:  # nothing left to fetch: the .part already has everything
            break
        resp.raise_for_status()
        failures = 0
        headers = resp.headers
        if resp.status_code == 200:  # server ignored Range and sent the whole file
            tmp.write_bytes(resp.content)
            break
        m = re.match(r"bytes (\d+)-(\d+)/(\d+)", resp.headers.get("content-range", ""))
        if not m or int(m.group(1)) != have:
            raise OSError(f"{src.name}: unexpected Content-Range {resp.headers.get('content-range')!r}")
        total = int(m.group(3))
        with tmp.open("ab") as f:
            f.write(resp.content)
        have += len(resp.content)
        if (have >> 20) % 5 == 0:
            log.info("%s: %d/%d MiB", src.name, have >> 20, total >> 20)

    return tmp, headers


async def sync_source(
    client: httpx.AsyncClient,
    src: Source,
    raw_dir: Path,
    manifest: dict[str, ManifestEntry],
    sem: asyncio.Semaphore,
) -> str:
    """Returns 'downloaded' or 'unchanged'."""
    dest = raw_dir / src.filename
    prior = manifest.get(src.name)
    async with sem:
        upstream: str | None = None
        if src.meta_url:
            upstream = await _upstream_nvd_sha(client, src.meta_url)
            if prior and prior.upstream_sha256 is None and dest.exists() and upstream:
                local = await asyncio.to_thread(gunzip_sha256, dest)  # backfill older manifests
                if local == upstream:
                    prior = prior.model_copy(update={"upstream_sha256": local})
                    manifest[src.name] = prior
            if prior and dest.exists() and upstream and upstream == prior.upstream_sha256:
                return "unchanged"

        fetch = _download_ranged if src.meta_url else _download_oneshot
        result = await fetch(client, src, dest, prior)
        if result is None:
            return "unchanged"
        tmp, headers = result

        digest = sha256_file(tmp)
        json_sha: str | None = None
        if src.meta_url:
            json_sha = await asyncio.to_thread(gunzip_sha256, tmp)
            if upstream and json_sha != upstream:  # the feed may have been rebuilt meanwhile
                upstream = await _upstream_nvd_sha(client, src.meta_url)
            if upstream and json_sha != upstream:
                bad = tmp.with_name(tmp.name.removesuffix(".part") + ".bad")
                tmp.replace(bad)  # keep for inspection; the next run starts clean
                raise OSError(f"{src.name}: SHA-256 mismatch (kept as {bad.name})")

    if prior and dest.exists() and prior.sha256 == digest:
        tmp.unlink()
        return "unchanged"

    tmp.replace(dest)
    manifest[src.name] = ManifestEntry(
        source=src.name,
        url=src.url,
        filename=src.filename,
        version=src.version,
        sha256=digest,
        size_bytes=dest.stat().st_size,
        downloaded_at=datetime.now(UTC).isoformat(timespec="seconds"),
        etag=headers.get("etag"),
        last_modified=headers.get("last-modified"),
        upstream_sha256=json_sha,
    )
    return "downloaded"


async def run(raw_dir: Path = RAW_DIR) -> dict[str, str]:
    raw_dir.mkdir(parents=True, exist_ok=True)
    manifest = load_manifest(raw_dir)
    sources = build_sources()
    sem = asyncio.Semaphore(NVD_CONCURRENCY)
    timeout = httpx.Timeout(60.0, read=300.0)
    headers = {"User-Agent": "redstring-cti/0.1 (research project)"}
    status: dict[str, str] = {}
    async with httpx.AsyncClient(follow_redirects=True, timeout=timeout, headers=headers) as client:

        async def one(src: Source) -> None:
            try:
                status[src.name] = await sync_source(client, src, raw_dir, manifest, sem)
            except (httpx.HTTPError, OSError) as exc:  # keep going; report at the end
                status[src.name] = f"FAILED: {exc!r}"
            else:
                save_manifest(raw_dir, manifest)  # checkpoint after each success
                log.info("%s: %s", src.name, status[src.name])

        await asyncio.gather(*(one(s) for s in sources))
    save_manifest(raw_dir, manifest)
    return status


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    status = asyncio.run(run())
    downloaded = sum(v == "downloaded" for v in status.values())
    unchanged = sum(v == "unchanged" for v in status.values())
    failed = {k: v for k, v in status.items() if v.startswith("FAILED")}
    print(f"downloaded={downloaded} unchanged={unchanged} failed={len(failed)}")
    for k, v in failed.items():
        print(f"  {k}: {v}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
