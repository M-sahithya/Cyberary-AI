"""
Cyberary-AI Configuration
Loads all settings from environment variables using Pydantic BaseSettings.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    APP_ENV: str = Field(default="development", description="Application environment")
    APP_NAME: str = Field(default="Cyberary-AI", description="Application name")
    APP_VERSION: str = Field(default="1.0.0", description="Application version")
    LAB_MODE: bool = Field(default=True, description="Enable lab-only mode (safety)")

    # --- Backend ---
    BACKEND_HOST: str = Field(default="0.0.0.0")
    BACKEND_PORT: int = Field(default=8000)

    # --- PostgreSQL ---
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://cyberary_user:change_me_in_production@postgres:5432/cyberary",
        description="PostgreSQL async connection string"
    )

    # --- MongoDB ---
    MONGODB_URL: str = Field(
        default="mongodb://cyberary_mongo:change_me_in_production@mongodb:27017/cyberary_logs?authSource=admin",
        description="MongoDB connection string"
    )
    MONGO_DB: str = Field(default="cyberary_logs", description="MongoDB database name")

    # --- JWT ---
    JWT_SECRET: str = Field(
        default="CHANGE_THIS_TO_A_RANDOM_64_CHAR_SECRET_IN_PRODUCTION",
        description="JWT signing secret"
    )
    JWT_ALGORITHM: str = Field(default="HS256")
    JWT_EXPIRY_HOURS: int = Field(default=24, description="JWT token expiry in hours")

    # --- LLM / AI ---
    LLM_PROVIDER: str = Field(default="ollama", description="LLM provider: ollama | openai")
    LLM_MODEL: str = Field(default="llama3", description="LLM model name")
    OLLAMA_BASE_URL: str = Field(default="http://ollama:11434")
    OPENAI_API_KEY: Optional[str] = Field(default=None)
    OPENAI_MODEL: str = Field(default="gpt-4")

    # --- NVD API ---
    NVD_API_KEY: Optional[str] = Field(default=None)
    NVD_BASE_URL: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0"
    )

    # --- Honeypot ---
    COWRIE_HOST: str = Field(default="honeypot")
    COWRIE_PORT: int = Field(default=2222)

    # --- Wazuh (Optional) ---
    WAZUH_URL: Optional[str] = Field(default=None)
    WAZUH_API_USER: Optional[str] = Field(default=None)
    WAZUH_API_PASSWORD: Optional[str] = Field(default=None)

    # --- Rate Limiting ---
    RATE_LIMIT_AUTH: str = Field(default="5/minute")
    RATE_LIMIT_API: str = Field(default="60/minute")

    # --- Default Admin ---
    DEFAULT_ADMIN_USERNAME: str = Field(default="admin")
    DEFAULT_ADMIN_PASSWORD: str = Field(default="CyberaryAdmin123!")
    DEFAULT_ADMIN_EMAIL: str = Field(default="admin@cyberary.local")

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": True,
    }


# Singleton settings instance
settings = Settings()
