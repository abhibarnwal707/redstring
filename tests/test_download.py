import asyncio
import gzip
import hashlib
from pathlib import Path

import httpx
import pytest

from redstring_cti.ingest import download

RAW = b"hello-cti"
BODY = gzip.compress(RAW)
SHA = hashlib.sha256(BODY).hexdigest()
RAW_SHA = hashlib.sha256(RAW).hexdigest()


def _handler(request: httpx.Request) -> httpx.Response:
    url = str(request.url)
    if url.endswith(".meta"):
        return httpx.Response(200, text=f"size:1\nsha256:{RAW_SHA.upper()}\n")
    if request.headers.get("if-none-match") == '"v1"':
        return httpx.Response(304)
    return httpx.Response(200, content=BODY, headers={"etag": '"v1"'})


@pytest.fixture
def patched_client(monkeypatch: pytest.MonkeyPatch) -> None:
    real = httpx.AsyncClient

    def factory(*args: object, **kwargs: object) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(_handler)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(download.httpx, "AsyncClient", factory)
    monkeypatch.setattr(download, "NVD_START_YEAR", 2025)


async def test_second_run_downloads_nothing(patched_client: None, tmp_path: Path) -> None:
    first = await download.run(tmp_path)
    assert first and all(v == "downloaded" for v in first.values())

    manifest = download.load_manifest(tmp_path)
    assert set(manifest) == set(first)
    assert all(e.sha256 == SHA and e.size_bytes == len(BODY) for e in manifest.values())

    second = await download.run(tmp_path)
    assert all(v == "unchanged" for v in second.values())
    assert not list(tmp_path.glob("*.part"))


def test_build_sources_pins_attack_and_covers_nvd_years() -> None:
    names = {s.name for s in download.build_sources()}
    assert {"attack", "cwe", "capec", "kev", "nvd-2002", "nvd-modified"} <= names


PAYLOAD_RAW = bytes(range(256)) * 400
PAYLOAD = gzip.compress(PAYLOAD_RAW, mtime=0)
PAYLOAD_SHA = hashlib.sha256(PAYLOAD).hexdigest()
PAYLOAD_RAW_SHA = hashlib.sha256(PAYLOAD_RAW).hexdigest()


def _range_server(fail_every: int) -> httpx.MockTransport:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url).endswith(".meta"):
            return httpx.Response(200, text=f"sha256:{PAYLOAD_RAW_SHA.upper()}\n")
        calls["n"] += 1
        if calls["n"] % fail_every == 0:
            raise httpx.ReadTimeout("stalled", request=request)
        start_s, _, end_s = request.headers["range"].removeprefix("bytes=").partition("-")
        start, end = int(start_s), min(int(end_s), len(PAYLOAD) - 1)
        if start >= len(PAYLOAD):
            return httpx.Response(416, headers={"content-range": f"bytes */{len(PAYLOAD)}"})
        return httpx.Response(
            206,
            content=PAYLOAD[start : end + 1],
            headers={"content-range": f"bytes {start}-{end}/{len(PAYLOAD)}", "etag": '"r1"'},
        )

    return httpx.MockTransport(handler)


async def test_ranged_download_resumes_and_survives_stalls(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(download, "CHUNK_BYTES", 1000)
    monkeypatch.setattr(download.asyncio, "sleep", lambda _s: _noop())
    src = download.Source(
        name="nvd-x", url="https://x/f.json.gz", filename="f.json.gz", version="x",
        meta_url="https://x/f.meta",
    )
    (tmp_path / "f.json.gz.part").write_bytes(PAYLOAD[:3500])  # interrupted earlier run

    async with httpx.AsyncClient(transport=_range_server(fail_every=3)) as client:
        manifest: dict[str, download.ManifestEntry] = {}
        status = await download.sync_source(client, src, tmp_path, manifest, asyncio.Semaphore(1))

    assert status == "downloaded"
    assert (tmp_path / "f.json.gz").read_bytes() == PAYLOAD
    assert manifest["nvd-x"].sha256 == PAYLOAD_SHA
    assert not (tmp_path / "f.json.gz.part").exists()


async def test_corrupt_partial_fails_sha_check_and_is_set_aside(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(download, "CHUNK_BYTES", 1000)
    src = download.Source(
        name="nvd-x", url="https://x/f.json.gz", filename="f.json.gz", version="x",
        meta_url="https://x/f.meta",
    )
    (tmp_path / "f.json.gz.part").write_bytes(b"\xff" * 2000)  # not a prefix of the payload

    async with httpx.AsyncClient(transport=_range_server(fail_every=10_000)) as client:
        with pytest.raises(OSError, match="SHA-256"):
            await download.sync_source(client, src, tmp_path, {}, asyncio.Semaphore(1))

    assert not (tmp_path / "f.json.gz.part").exists()
    assert not (tmp_path / "f.json.gz").exists()
    assert (tmp_path / "f.json.gz.bad").exists()  # never deleted, kept for inspection


async def _noop() -> None:
    return None


async def test_nvd_skip_uses_uncompressed_sha_and_backfills_old_manifest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    src = download.Source(
        name="nvd-x", url="https://x/f.json.gz", filename="f.json.gz", version="x",
        meta_url="https://x/f.meta",
    )
    (tmp_path / "f.json.gz").write_bytes(PAYLOAD)
    old = download.ManifestEntry(  # written before upstream_sha256 existed
        source="nvd-x", url=src.url, filename=src.filename, version="x", sha256=PAYLOAD_SHA,
        size_bytes=len(PAYLOAD), downloaded_at="2026-01-01T00:00:00+00:00",
    )
    manifest = {"nvd-x": old}

    def no_network(request: httpx.Request) -> httpx.Response:
        assert str(request.url).endswith(".meta"), "must not re-download"
        return httpx.Response(200, text=f"sha256:{PAYLOAD_RAW_SHA}\n")

    async with httpx.AsyncClient(transport=httpx.MockTransport(no_network)) as client:
        status = await download.sync_source(client, src, tmp_path, manifest, asyncio.Semaphore(1))

    assert status == "unchanged"
    assert manifest["nvd-x"].upstream_sha256 == PAYLOAD_RAW_SHA
