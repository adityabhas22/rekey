"""Application configuration loaded from env / `.env`.

Only rekey's own settings live here. External-tool env vars (OP_SERVICE_ACCOUNT_TOKEN,
BW_SESSION, ANTHROPIC_API_KEY etc.) are read directly by the relevant adapters
since they don't share the ``REKEY_`` prefix.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """rekey runtime configuration."""

    # Web dashboard
    web_host: str = "127.0.0.1"
    web_port: int = 7777

    # Browser / Chrome CDP
    cdp_port: int = 9222

    # CSV imports — comma-separated list of paths
    csv_paths: str = ""

    # LLM override (optional — adapter auto-detects if not set)
    llm_provider: str = ""
    llm_model: str = ""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="REKEY_",
        extra="ignore",
    )

    @property
    def csv_paths_list(self) -> list[str]:
        return [p.strip() for p in self.csv_paths.split(",") if p.strip()]
