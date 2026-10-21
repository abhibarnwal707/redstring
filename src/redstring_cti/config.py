from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ATTACK_VERSION = "20.0"
NVD_START_YEAR = 2002
RAW_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str
    ollama_host: str = "http://localhost:11434"
    groq_api_key: str = ""


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
