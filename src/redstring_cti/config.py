from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ATTACK_VERSION = "20.0"
NVD_START_YEAR = 2002
RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"
PROCESSED_DIR = Path(__file__).resolve().parents[2] / "data" / "processed"

# Groq free-tier chat models, best first. A rate-limit wait retries the SAME model; only a hard
# failure (daily quota exhausted, model removed, repeated 5xx) moves to the next one, and every
# result records the model that produced it.
LLM_MODELS = ("openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b")

# OpenRouter free models (spec prefix selects the provider). Free models are flaky (provider 404s,
# upstream 429s), so this is an ordered chain with fast failover. `openrouter/free` is deliberately
# absent: it routes each call to a random model, which breaks reproducibility.
OPENROUTER_FREE_MODELS = (
    "openrouter:minimax/minimax-m3.1-flash:free",
    "openrouter:nvidia/nemotron-3-super-120b-a12b:free",
    "openrouter:google/gemma-4-31b-it:free",
)
LLM_CHAINS: dict[str, tuple[str, ...]] = {
    # Evaluation default: ONE model, no silent fallback. Groq's free tier has a daily TOKEN cap
    # (about 285K tokens/day was observed on gpt-oss-120b), and mixing models in a comparison is worse
    # than waiting for the quota to reset: runs are resumable, so they just stop and continue later.
    "groq-120b": LLM_MODELS[:1],
    "groq": LLM_MODELS,  # all three Groq models, falling back on hard failures
    "openrouter": OPENROUTER_FREE_MODELS,
    "groq+openrouter": (*LLM_MODELS, *OPENROUTER_FREE_MODELS),  # OpenRouter only if every Groq model fails hard
}

# Reference prices in USD per million tokens (input, output): Groq list prices read from
# https://console.groq.com/docs/models on 2026-10-21. Used to report $/query even though the free
# tier costs nothing; re-check before quoting them.
REFERENCE_PRICES_USD_PER_M: dict[str, tuple[float, float]] = {
    "openai/gpt-oss-120b": (0.15, 0.60),
    "openai/gpt-oss-20b": (0.075, 0.30),
    "qwen/qwen3.8-27b": (0.80, 4.00),
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str
    ollama_host: str = "http://localhost:11434"
    groq_api_key: str = ""
    openrouter_api_key: str = ""
    # OpenRouter allows 50 free-model requests/day below $10 of purchased credits and 1000/day above;
    # stay under the limit so the counter never lets a run burn the whole allowance.
    openrouter_daily_limit: int = 45


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
