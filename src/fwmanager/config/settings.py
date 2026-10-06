"""Configuration settings for Linux Firewall Manager."""

from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_prefix="FW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Linux Firewall Manager"
    app_version: str = "0.1.0"
    app_env: Literal["development", "testing", "production"] = "development"
    debug: bool = False

    # Firewall execution engine
    backend: Literal["simulation", "nftables", "iptables"] = "simulation"
    auto_rollback_timeout: int = Field(
        default=30,
        ge=5,
        le=300,
        description="Auto-rollback timeout in seconds for safety verification",
    )

    # API configuration
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    log_level: str = "INFO"


settings = Settings()
