"""Create (or update) the Hugging Face Space and upload the bundle: `python deploy/create_space.py` (PRIVATE by default).

Secrets come from .env and are sent to Hugging Face as Space secrets; nothing is printed. The in-container Neo4j gets a fresh
random password (it listens on localhost only), not your local one."""

import argparse
import os
import secrets
import sys
from pathlib import Path

from dotenv import load_dotenv
from huggingface_hub import HfApi

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", default="abhibarnwal707/redstring-cti")
    ap.add_argument("--public", action="store_true", help="make the Space public (default: private)")
    ap.add_argument("--keep-neo4j-password", action="store_true", help="do not rotate the in-container Neo4j password")
    args = ap.parse_args()
    load_dotenv(ROOT / ".env")
    token = os.environ["HF_TOKEN"]
    api = HfApi(token=token)
    bundle = ROOT / "build" / "space"
    if not (bundle / "Dockerfile").exists():
        sys.exit("run `python deploy/build_space_bundle.py` first")
    api.create_repo(args.repo, repo_type="space", space_sdk="docker", private=not args.public, exist_ok=True)
    api.add_space_secret(args.repo, "HF_TOKEN", token)
    api.add_space_secret(args.repo, "GROQ_API_KEY", os.environ["GROQ_API_KEY"])
    if not args.keep_neo4j_password:
        api.add_space_secret(args.repo, "NEO4J_PASSWORD", secrets.token_urlsafe(24))
    api.upload_folder(folder_path=str(bundle), repo_id=args.repo, repo_type="space", commit_message="Deploy RedString-CTI")
    print("uploaded to", args.repo, "(public)" if args.public else "(private)")


if __name__ == "__main__":
    main()
