"""`uv run python evals/runners/compare_runs.py vector_rag-dev text2cypher-dev` writes evals/results/baselines.md."""

from redstring_cti.evaluation import compare_main

if __name__ == "__main__":
    compare_main()
