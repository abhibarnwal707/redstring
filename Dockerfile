# Runtime image for the MCP server, the agent and the CLIs. Neo4j runs separately (docker-compose.yml).
FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:0.8 /uv /usr/local/bin/uv
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_NO_CACHE=1 PYTHONUNBUFFERED=1 HF_HOME=/models

# dependencies first, so code changes do not reinstall them
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-install-project --no-dev

COPY src ./src
COPY evals/gold ./evals/gold
RUN uv sync --frozen --no-dev

# configuration comes from the environment (NEO4J_URI, NEO4J_PASSWORD, GROQ_API_KEY ...), never from the image
ENTRYPOINT ["uv", "run", "--no-sync"]
CMD ["python", "-m", "redstring_cti.mcp_server.server"]
