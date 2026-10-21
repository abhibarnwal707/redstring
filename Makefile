.PHONY: download load embed test lint eval up down

download:
	uv run python -m redstring_cti.ingest.download

load:
	uv run python -m redstring_cti.graph.loader

test:
	uv run pytest

lint:
	uv run ruff check . && uv run mypy src

eval:
	uv run python evals/runners/run_rag_eval.py

up:
	docker compose up -d

down:
	docker compose down

embed:
	uv run python -m redstring_cti.graph.embeddings
