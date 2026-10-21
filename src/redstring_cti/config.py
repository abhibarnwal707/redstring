from pydantic_settings import BaseSettings, SettingsConfigDict

ATTACK_VERSION = "20.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str
    ollama_host: str = "http://localhost:11434"


def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
