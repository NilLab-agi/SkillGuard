"""Runtime configuration, read from the environment.

Anything an operator may tune lives here. Anything that must never change at
runtime lives in constants.py.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from skillguard.constants import MAX_FILE_BYTES_DEFAULT, MAX_FILES_DEFAULT


class Settings(BaseSettings):
    """SkillGuard settings. Environment variables use the SKILLGUARD_ prefix"""

    model_config = SettingsConfigDict(
        env_prefix="SKILLGUARD_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    provider: str = "deepseek"
    model: str = "deepseek-flash"
    base_url: str | None = None
    api_key: SecretStr | None = None
    llm_timeout: float = Field(default=30.0, gt=0)

    max_file_bytes: int = Field(default=MAX_FILE_BYTES_DEFAULT, gt=0)
    max_files: int = Field(default=MAX_FILES_DEFAULT, gt=0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    @field_validator("api_key", mode="before")
    @classmethod
    def _blank_to_none(cls, value: object) -> object:
        """Treat an empty SKILLGUARD_API_KEY= as absent, not as an empty secret."""
        if isinstance(value, str) and not value.strip():
            return None
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, parsed once."""
    return Settings()
