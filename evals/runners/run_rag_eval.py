"""Thin entry point: `uv run python evals/runners/run_rag_eval.py --system vector_rag --split dev`."""

from redstring_cti.evaluation import main

if __name__ == "__main__":
    main()
