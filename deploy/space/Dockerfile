# Hugging Face Space (Docker SDK, free CPU): Neo4j and the Gradio app in ONE container.
# Neo4j and Java are copied from the official Neo4j image; the subset graph is downloaded at start (entrypoint.sh).
FROM neo4j:5-community AS neo4j

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
COPY --from=neo4j /var/lib/neo4j /opt/neo4j
COPY --from=neo4j /opt/java/openjdk /opt/java
ENV JAVA_HOME=/opt/java NEO4J_HOME=/opt/neo4j PATH=/opt/java/bin:/opt/neo4j/bin:$PATH \
    UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_CACHE=1 PYTHONUNBUFFERED=1 HF_HOME=/home/user/hf

# Hugging Face runs Spaces as user 1000
# the official image symlinks logs/run/data/import to root-owned paths that do not exist here: use real directories
RUN useradd -m -u 1000 user && mkdir -p /app /data /home/user/hf \
 && for d in logs run data import; do rm -rf /opt/neo4j/$d; mkdir -p /opt/neo4j/$d; done \
 && chown -R user:user /opt/neo4j /app /data /home/user
WORKDIR /app
COPY --chown=user:user pyproject.toml uv.lock README.md ./
USER user
RUN uv sync --frozen --no-install-project --no-dev
COPY --chown=user:user src ./src
COPY --chown=user:user evals ./evals
RUN uv sync --frozen --no-dev
# CPU wheel of llama.cpp for the quantised extractor (amd64 on Hugging Face; the install is allowed to fail on other architectures)
RUN uv pip install --python .venv/bin/python llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu || echo 'llama-cpp-python not installed on this architecture'
# the embedding model is part of the image so the first question is not slow
RUN uv run --no-sync python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('BAAI/bge-small-en-v1.5')"
COPY --chown=user:user entrypoint.sh /app/entrypoint.sh
ENV PORT=7860 NEO4J_URI=bolt://127.0.0.1:7687 REDSTRING_EXTRACTOR=llama REDSTRING_MAX_CHUNKS=2
EXPOSE 7860
CMD ["bash", "/app/entrypoint.sh"]
