"""Upload the subset graph dump to a PRIVATE Hugging Face dataset repo (the Space downloads it at start)."""

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="abhibarnwal707/redstring-cti-graph-subset")
    ap.add_argument("--file", type=Path, default=ROOT / "data" / "dumps" / "subset" / "neo4j.dump")
    args = ap.parse_args()
    load_dotenv(ROOT / ".env")
    api = HfApi(token=os.environ["HF_TOKEN"])
    api.create_repo(args.repo, repo_type="dataset", private=True, exist_ok=True)
    api.upload_file(path_or_fileobj=str(args.file), path_in_repo="neo4j.dump", repo_id=args.repo, repo_type="dataset")
    print("uploaded", args.file, "to", args.repo, "(private dataset)")


if __name__ == "__main__":
    main()
