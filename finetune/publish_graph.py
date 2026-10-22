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
    ap.add_argument("--public", action="store_true")
    args = ap.parse_args()
    load_dotenv(ROOT / ".env")
    api = HfApi(token=os.environ["HF_TOKEN"])
    api.create_repo(args.repo, repo_type="dataset", private=not args.public, exist_ok=True)
    api.upload_file(path_or_fileobj=str(args.file), path_in_repo="neo4j.dump", repo_id=args.repo, repo_type="dataset")
    card = Path(__file__).parent / "GRAPH_README.md"
    if card.exists():
        api.upload_file(path_or_fileobj=str(card), path_in_repo="README.md", repo_id=args.repo, repo_type="dataset")
    if args.public:
        api.update_repo_settings(args.repo, repo_type="dataset", private=False)
    print("uploaded", args.file, "to", args.repo, "(public dataset)" if args.public else "(private dataset)")


if __name__ == "__main__":
    main()
