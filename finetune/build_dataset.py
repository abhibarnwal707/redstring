"""Thin entry point (the playbook's layout): `uv run python finetune/build_dataset.py` == `make finetune-data`."""

from redstring_cti.extractor.dataset import main

if __name__ == "__main__":
    main()
