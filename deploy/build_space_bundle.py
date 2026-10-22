"""Assemble the folder that is pushed to the Hugging Face Space repo: `python deploy/build_space_bundle.py` -> build/space/."""

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "build" / "space"


def main() -> None:
    if OUT.exists():
        shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    for name in ("pyproject.toml", "uv.lock"):
        shutil.copy2(ROOT / name, OUT / name)
    for name in ("Dockerfile", "entrypoint.sh", "README.md"):
        shutil.copy2(ROOT / "deploy" / "space" / name, OUT / name)
    shutil.copytree(ROOT / "src", OUT / "src", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    (OUT / "evals" / "gold").mkdir(parents=True)
    for f in (ROOT / "evals" / "gold").glob("*"):
        if f.is_file():
            shutil.copy2(f, OUT / "evals" / "gold" / f.name)
    (OUT / "evals" / "results").mkdir()
    for name in ("extractor_comparison.md", "extractor_verdict.md", "extractor_quantization.md", "baselines.md", "data_quality.md"):
        if (ROOT / "evals" / "results" / name).exists():
            shutil.copy2(ROOT / "evals" / "results" / name, OUT / "evals" / "results" / name)
    print("bundle written to", OUT)


if __name__ == "__main__":
    main()
