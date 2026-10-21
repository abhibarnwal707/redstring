.PHONY: download load embed dq gold test lint eval eval-vector eval-t2c serve up down

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

dq:
	uv run python -m redstring_cti.graph.dq

gold:
	uv run python -m redstring_cti.gold.build

eval-vector:
	uv run python evals/runners/run_rag_eval.py --system vector_rag --split dev

eval-t2c:
	uv run python evals/runners/run_rag_eval.py --system text2cypher --split dev

serve:
	uv run python -m redstring_cti.mcp_server.server
