# backend/app/core/config.py
"""Application configuration using Pydantic Settings."""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Application
    APP_NAME: str = "ai-security-scanner"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"

    # API
    API_PREFIX: str = "/api/v1"
    ALLOWED_ORIGINS: str = Field(
        default="http://localhost:3000",
        description="Comma-separated list of allowed CORS origins",
    )

    # Scanner Settings
    DEFAULT_CONCURRENCY: int = 5
    REQUEST_TIMEOUT: int = 30
    MAX_INPUT_LENGTH: int = 10000

    # Web Mode Security
    SANDBOX_URL: str = "https://rag-api.musabdulai.com"
    RATE_LIMIT_REQUESTS: int = 1
    RATE_LIMIT_WINDOW: int = 300  # 5 minutes per IP

    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.ENVIRONMENT == "production"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()
