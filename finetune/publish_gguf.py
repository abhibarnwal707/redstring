"""Upload the quantised GGUF to a Hugging Face model repo (PRIVATE by default; flip it public in the repo settings)."""

import argparse
import os
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import HfApi

HERE = Path(__file__).parent


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="abhibarnwal707/redstring-cti-extractor-qwen3-1.7b-v2-GGUF")
    ap.add_argument("--file", type=Path, default=HERE / "gguf" / "redstring-extractor-q4_k_m.gguf")
    ap.add_argument("--public", action="store_true")
    args = ap.parse_args()
    load_dotenv(HERE.parent / ".env")
    token = os.environ["HF_TOKEN"]
    api = HfApi(token=token)
    api.create_repo(args.repo, private=not args.public, exist_ok=True)
    readme = HERE / "GGUF_README.md"
    api.upload_file(path_or_fileobj=str(args.file), path_in_repo=args.file.name, repo_id=args.repo)
    if readme.exists():
        api.upload_file(path_or_fileobj=str(readme), path_in_repo="README.md", repo_id=args.repo)
    print("uploaded", args.file.name, "to", args.repo, "(public)" if args.public else "(private)")


if __name__ == "__main__":
    main()
