"""One-command local setup: `make doctor`, `make quickstart` (or the pieces: `graph-restore`, `model-fetch`).

* doctor        checks the machine (RAM, disk, Docker, Ollama, ports, .env) and says what is missing
* graph-restore starts Neo4j in Docker and loads the published graph dump into it (no 1-hour rebuild from the sources)
* model-fetch   downloads our quantised extractor (GGUF) and registers it with Ollama
* quickstart    all of the above, then a smoke test

Safety: graph-restore refuses to overwrite an existing database unless `--force`."""

import argparse
import os
import platform
import secrets
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = ROOT / ".env"
GRAPH_REPO = "abhibarnwal707/redstring-cti-graph-subset"
MODEL_REPO = "abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-v2-GGUF"
MODEL_FILE = "redstring-extractor-q8_0.gguf"
OLLAMA_MODEL = "redstring-extractor"
MIN_RAM_GB, GOOD_RAM_GB, MIN_DISK_GB = 8.0, 16.0, 15.0
MIN_NODES = 100_000  # the published subset has 109,515


@dataclass
class Check:
    name: str
    status: str  # OK | WARN | FAIL
    detail: str

    def line(self) -> str:
        return f"[{self.status:4}] {self.name}: {self.detail}"


# ---------------------------------------------------------------------------- machine facts
def total_ram_gb() -> float | None:
    system = platform.system()
    try:
        if system == "Darwin":
            return int(subprocess.run(["sysctl", "-n", "hw.memsize"], capture_output=True, text=True, check=True).stdout) / 1e9
        if system == "Linux":
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1]) * 1024 / 1e9
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return None


def run_quiet(cmd: list[str], timeout: float = 20.0) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None


def port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ollama_running(url: str = "http://localhost:11434") -> bool:
    try:
        return httpx.get(f"{url}/api/version", timeout=2.0).status_code == 200
    except httpx.HTTPError:
        return False


def read_env(path: Path = ENV_PATH) -> dict[str, str]:
    out: dict[str, str] = {}
    if path.exists():
        for line in path.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip()
    return out


def ensure_env(path: Path = ENV_PATH) -> dict[str, str]:
    """Create .env from .env.example if missing and give Neo4j a random password if it has none."""
    if not path.exists():
        example = ROOT / ".env.example"
        path.write_text(example.read_text() if example.exists() else "")
    env = read_env(path)
    if not env.get("NEO4J_PASSWORD"):
        password = secrets.token_urlsafe(18)
        lines = [ln for ln in path.read_text().splitlines() if not ln.startswith("NEO4J_PASSWORD=")]
        path.write_text("\n".join([*lines, f"NEO4J_PASSWORD={password}"]) + "\n")
        env = read_env(path)
        print("created a random NEO4J_PASSWORD in .env")
    return env


# ---------------------------------------------------------------------------- doctor
def doctor(root: Path = ROOT) -> list[Check]:
    checks: list[Check] = []
    ram = total_ram_gb()
    if ram is None:
        checks.append(Check("memory", "WARN", "could not read total RAM (need 8 GB minimum, 16 GB recommended)"))
    elif ram < MIN_RAM_GB:
        checks.append(Check("memory", "FAIL", f"{ram:.0f} GB RAM; Neo4j, the embedding model and the extractor need at least {MIN_RAM_GB:.0f} GB"))
    elif ram < GOOD_RAM_GB:
        checks.append(Check("memory", "WARN", f"{ram:.0f} GB RAM works but is tight; 16 GB is comfortable"))
    else:
        checks.append(Check("memory", "OK", f"{ram:.0f} GB RAM"))
    free = shutil.disk_usage(root).free / 1e9
    checks.append(Check("disk", "OK" if free >= MIN_DISK_GB else "FAIL", f"{free:.0f} GB free in the project folder (need about {MIN_DISK_GB:.0f} GB: dependencies 3, graph 3, model 2, caches 2)"))
    checks.append(Check("platform", "OK" if platform.system() in ("Darwin", "Linux") else "WARN",
                        f"{platform.system()} {platform.machine()}" + ("" if platform.system() in ("Darwin", "Linux") else " (Windows: use WSL2; this project was tested on macOS only)")))
    checks.append(Check("python", "OK" if sys.version_info >= (3, 12) else "WARN", f"Python {sys.version.split()[0]} (uv installs 3.12 for the project automatically)"))
    for tool, hint in [("uv", "https://docs.astral.sh/uv/getting-started/installation/"), ("git", "https://git-scm.com/downloads")]:
        checks.append(Check(tool, "OK" if shutil.which(tool) else "FAIL", "found" if shutil.which(tool) else f"not found: {hint}"))
    if not shutil.which("docker"):
        checks.append(Check("docker", "FAIL", "not found: install Docker Desktop (https://docs.docker.com/get-docker/)"))
    else:
        proc = run_quiet(["docker", "info", "--format", "{{.ServerVersion}}"])
        if proc is not None and proc.returncode == 0:
            checks.append(Check("docker", "OK", f"daemon running (server {proc.stdout.strip()})"))
        else:
            checks.append(Check("docker", "FAIL", "installed but the daemon is not running: start Docker Desktop"))
    if not shutil.which("ollama"):
        checks.append(Check("ollama", "WARN", "not found: install from https://ollama.com/download (needed for the Extract tab and `make ingest-report`; the graph and agent work without it)"))
    else:
        checks.append(Check("ollama", "OK" if ollama_running() else "WARN", "installed and running" if ollama_running() else "installed but not running: open the Ollama app or run `ollama serve`"))
    env = read_env(root / ".env")
    checks.append(Check(".env", "OK" if env.get("NEO4J_PASSWORD") else "WARN", "NEO4J_PASSWORD set" if env.get("NEO4J_PASSWORD") else "no NEO4J_PASSWORD yet: `make quickstart` creates one"))
    checks.append(Check("GROQ_API_KEY", "OK" if env.get("GROQ_API_KEY") else "WARN", "set" if env.get("GROQ_API_KEY") else "not set: needed only for the Ask tab (free key at https://console.groq.com/keys)"))
    for port, what in [(7687, "Neo4j"), (7860, "the app")]:
        if port_in_use(port):
            checks.append(Check(f"port {port}", "WARN", f"already in use (fine if it is your own {what}; otherwise change NEO4J_BOLT_PORT / PORT)"))
    return checks


# ---------------------------------------------------------------------------- graph
def compose(*args: str, env_extra: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **read_env(), **(env_extra or {})}
    return subprocess.run(["docker", "compose", *args], cwd=ROOT, env=env, text=True, check=check, capture_output=False)


def data_dir() -> Path:
    path = Path(os.environ.get("NEO4J_DATA_DIR", read_env().get("NEO4J_DATA_DIR", "./data/neo4j")))
    return path if path.is_absolute() else ROOT / path


def has_database(path: Path) -> bool:
    return (path / "databases" / "neo4j" / "neostore").exists()


def download_dump(dest_dir: Path, repo: str = GRAPH_REPO) -> Path:
    from huggingface_hub import hf_hub_download

    dest_dir.mkdir(parents=True, exist_ok=True)
    return Path(hf_hub_download(repo, "neo4j.dump", repo_type="dataset", local_dir=str(dest_dir)))


def wait_for_neo4j(timeout_s: float = 180.0) -> int:
    """Waits until the graph answers and returns its node count."""
    from neo4j import GraphDatabase

    env = {**read_env(), **os.environ}
    uri = env.get("NEO4J_URI", "bolt://localhost:7687")
    deadline = time.time() + timeout_s
    last: Exception | None = None
    while time.time() < deadline:
        driver = GraphDatabase.driver(uri, auth=(env.get("NEO4J_USER", "neo4j"), env["NEO4J_PASSWORD"]))
        try:
            records, _, _ = driver.execute_query("MATCH (n) RETURN count(n) AS n")
            return int(records[0]["n"])
        except Exception as exc:  # noqa: BLE001  the server is still starting
            last = exc
            time.sleep(3)
        finally:
            driver.close()
    raise RuntimeError(f"Neo4j did not come up within {timeout_s:.0f}s: {last}")


def restore_graph(force: bool = False) -> int:
    ensure_env()
    target = data_dir()
    if has_database(target) and not force:
        print(f"{target} already holds a database. Not touching it (use --force to replace it).")
        compose("up", "-d", "neo4j")
        return wait_for_neo4j()
    dump_dir = ROOT / "data" / "dumps" / "published"
    print(f"downloading the graph dump from {GRAPH_REPO} (about 700 MB)")
    dump = download_dump(dump_dir)
    compose("stop", "neo4j", check=False)
    target.mkdir(parents=True, exist_ok=True)
    print("loading it into Neo4j")
    subprocess.run(["docker", "run", "--rm", "-v", f"{target}:/data", "-v", f"{dump.parent}:/dumps", "neo4j:5-community",
                    "neo4j-admin", "database", "load", "neo4j", "--from-path=/dumps", "--overwrite-destination=true"], check=True)
    compose("up", "-d", "neo4j")
    nodes = wait_for_neo4j()
    if nodes < MIN_NODES:
        raise RuntimeError(f"the restored graph has only {nodes} nodes (expected about 109,500)")
    print(f"graph ready: {nodes:,} nodes")
    return nodes


# ---------------------------------------------------------------------------- model
def model_registered(name: str = OLLAMA_MODEL) -> bool:
    proc = run_quiet(["ollama", "list"])
    return proc is not None and any(line.split()[0].split(":")[0] == name for line in proc.stdout.splitlines()[1:] if line.strip())


def fetch_model(force: bool = False) -> None:
    from huggingface_hub import hf_hub_download

    if not shutil.which("ollama"):
        raise RuntimeError("Ollama is not installed (https://ollama.com/download). Alternative without Ollama: set REDSTRING_EXTRACTOR=hf (downloads the base model and our adapter, about 4 GB).")
    if not ollama_running():
        raise RuntimeError("Ollama is installed but not running: open the Ollama app or run `ollama serve`.")
    if model_registered() and not force:
        print(f"Ollama already has '{OLLAMA_MODEL}' (use --force to rebuild it)")
        return
    models = ROOT / "data" / "models"
    models.mkdir(parents=True, exist_ok=True)
    print(f"downloading {MODEL_FILE} from {MODEL_REPO} (about 1.8 GB)")
    gguf = Path(hf_hub_download(MODEL_REPO, MODEL_FILE, local_dir=str(models)))
    modelfile = models / "Modelfile"
    modelfile.write_text(f'FROM {gguf}\nPARAMETER temperature 0\nPARAMETER num_predict 700\nPARAMETER num_ctx 4096\nPARAMETER stop "<|im_end|>"\n')
    subprocess.run(["ollama", "create", OLLAMA_MODEL, "-f", str(modelfile)], check=True)
    print(f"registered '{OLLAMA_MODEL}' with Ollama")


# ---------------------------------------------------------------------------- smoke test and quickstart
def smoke_test() -> list[Check]:
    from redstring_cti.extractor.backends import OllamaExtractor
    from redstring_cti.graph.loader import get_driver
    from redstring_cti.mcp_server import tools

    checks: list[Check] = []
    driver = get_driver()
    ctx = tools.Context(driver=driver, embed=lambda text: [0.0] * 384)
    found = tools.resolve_entity(ctx, "Cozy Bear")["candidates"][0]["id"]
    checks.append(Check("graph", "OK" if found == "G0016" else "FAIL", f"'Cozy Bear' resolves to {found} (expected G0016)"))
    paths = tools.find_paths(ctx, "G0016", "CVE", kev_only=True, limit=3)["endpoint_count"]
    checks.append(Check("graph paths", "OK" if paths > 0 else "FAIL", f"{paths} actively exploited CVEs reachable from APT29 through CAPEC and CWE"))
    if shutil.which("ollama") and ollama_running() and model_registered():
        out = OllamaExtractor(OLLAMA_MODEL)("entities_techniques", "Cozy Bear used Cobalt Strike and spearphishing attachments.")
        checks.append(Check("extractor", "OK" if '"entities"' in out else "FAIL", out[:90]))
    else:
        checks.append(Check("extractor", "WARN", "Ollama model not available: the Extract tab will not work until `make model-fetch` succeeds"))
    return checks


def quickstart(force: bool = False) -> int:
    print("== 1/4 checking this machine")
    checks = doctor()
    for c in checks:
        print(c.line())
    if any(c.status == "FAIL" for c in checks):
        print("\nFix the FAIL lines above and run `make quickstart` again.")
        return 1
    print("\n== 2/4 graph")
    restore_graph(force=force)
    print("\n== 3/4 extractor model")
    try:
        fetch_model()
    except RuntimeError as exc:
        print(f"skipped: {exc}")
    print("\n== 4/4 smoke test")
    results = smoke_test()
    for c in results:
        print(c.line())
    bad = [c for c in results if c.status == "FAIL"]
    print("\nReady. Start the app with:  make app   (then open http://localhost:7860)" if not bad else "\nSomething failed: see the lines above.")
    return 1 if bad else 0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["doctor", "graph-restore", "model-fetch", "quickstart"])
    ap.add_argument("--force", action="store_true", help="replace an existing graph / rebuild the Ollama model")
    args = ap.parse_args()
    if args.command == "doctor":
        checks = doctor()
        print("\n".join(c.line() for c in checks))
        raise SystemExit(1 if any(c.status == "FAIL" for c in checks) else 0)
    if args.command == "graph-restore":
        restore_graph(force=args.force)
    elif args.command == "model-fetch":
        fetch_model(force=args.force)
    else:
        raise SystemExit(quickstart(force=args.force))


if __name__ == "__main__":
    main()
