from pathlib import Path

import pytest

from redstring_cti import local_setup


def test_read_env_parses_values_and_ignores_comments(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("# comment\nNEO4J_PASSWORD=abc=def\n\nGROQ_API_KEY=\n  SPACED = value \n")
    assert local_setup.read_env(env) == {"NEO4J_PASSWORD": "abc=def", "GROQ_API_KEY": "", "SPACED": "value"}
    assert local_setup.read_env(tmp_path / "missing") == {}


def test_ensure_env_creates_a_random_password_once_and_keeps_other_keys(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("GROQ_API_KEY=keep-me\nNEO4J_PASSWORD=\n")
    first = local_setup.ensure_env(env)
    assert first["GROQ_API_KEY"] == "keep-me" and len(first["NEO4J_PASSWORD"]) >= 20
    assert local_setup.ensure_env(env)["NEO4J_PASSWORD"] == first["NEO4J_PASSWORD"]  # a second call changes nothing
    assert env.read_text().count("NEO4J_PASSWORD=") == 1
    (tmp_path / "new").mkdir()
    assert local_setup.ensure_env(tmp_path / "new" / ".env")["NEO4J_PASSWORD"]


def test_has_database_detects_an_existing_graph(tmp_path: Path) -> None:
    assert not local_setup.has_database(tmp_path)
    store = tmp_path / "databases" / "neo4j"
    store.mkdir(parents=True)
    (store / "neostore").write_text("x")
    assert local_setup.has_database(tmp_path)


def test_doctor_reports_each_requirement(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(local_setup, "total_ram_gb", lambda: 4.0)
    monkeypatch.setattr(local_setup.shutil, "which", lambda name: None)
    monkeypatch.setattr(local_setup, "port_in_use", lambda port: False)
    checks = {c.name: c for c in local_setup.doctor(tmp_path)}
    assert checks["memory"].status == "FAIL" and "8 GB" in checks["memory"].detail
    assert checks["docker"].status == "FAIL" and checks["uv"].status == "FAIL"
    assert checks["ollama"].status == "WARN"  # optional: the graph and agent work without it
    assert checks["GROQ_API_KEY"].status == "WARN" and checks[".env"].status == "WARN"
    monkeypatch.setattr(local_setup, "total_ram_gb", lambda: 16.0)
    assert {c.name: c for c in local_setup.doctor(tmp_path)}["memory"].status == "OK"
    monkeypatch.setattr(local_setup, "total_ram_gb", lambda: 12.0)
    assert {c.name: c for c in local_setup.doctor(tmp_path)}["memory"].status == "WARN"
    monkeypatch.setattr(local_setup, "total_ram_gb", lambda: None)
    assert {c.name: c for c in local_setup.doctor(tmp_path)}["memory"].status == "WARN"


def test_restore_refuses_to_overwrite_an_existing_graph_without_force(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = tmp_path / "databases" / "neo4j"
    store.mkdir(parents=True)
    (store / "neostore").write_text("x")
    calls: list[str] = []
    monkeypatch.setenv("NEO4J_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(local_setup, "ensure_env", lambda path=None: {"NEO4J_PASSWORD": "x"})
    monkeypatch.setattr(local_setup, "compose", lambda *a, **k: calls.append(" ".join(a)))  # type: ignore[arg-type,return-value]
    monkeypatch.setattr(local_setup, "wait_for_neo4j", lambda timeout_s=180.0: 123456)
    monkeypatch.setattr(local_setup, "download_dump", lambda *a, **k: pytest.fail("must not download when a graph exists"))
    assert local_setup.restore_graph() == 123456
    assert calls == ["up -d neo4j"]  # started it, did not stop or replace it


def test_fetch_model_explains_what_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(local_setup.shutil, "which", lambda name: None)
    with pytest.raises(RuntimeError, match="not installed"):
        local_setup.fetch_model()
    monkeypatch.setattr(local_setup.shutil, "which", lambda name: "/usr/bin/ollama")
    monkeypatch.setattr(local_setup, "ollama_running", lambda url="": False)
    with pytest.raises(RuntimeError, match="not running"):
        local_setup.fetch_model()
