.PHONY: download load embed dq gold test lint eval eval-vector eval-t2c eval-agent sanity-agent finetune-data kaggle-notebook eval-extractor ingest-report update app serve up down

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

eval-agent:
	uv run python evals/runners/run_rag_eval.py --system agent --split dev

sanity-agent:
	uv run python -m redstring_cti.agent.sanity

finetune-data:
	uv run python finetune/build_dataset.py

kaggle-notebook:
	uv run python scripts/py_to_ipynb.py finetune/notebooks/train_qlora.py finetune/notebooks/train_qlora.ipynb
	uv run python scripts/py_to_ipynb.py finetune/notebooks/eval_from_checkpoint.py finetune/notebooks/eval_from_checkpoint.ipynb

SPLIT ?= val
eval-extractor:
	uv run python evals/runners/run_extractor_eval.py --split $(SPLIT)

URL ?=
ingest-report:
	uv run python -m redstring_cti.extractor.ingest_report "$(URL)" $(ARGS)

update:
	uv run python -m redstring_cti.update $(ARGS)

app:
	uv run python -m redstring_cti.app
