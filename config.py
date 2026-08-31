"""Configuration settings for the Multi-Agent SOC Triage and Alert Correlation System."""

import os
from pathlib import Path
from typing import Optional, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent

class Settings(BaseSettings):
    # App Settings
    APP_NAME: str = "AegisSOC Multi-Agent Autonomous Triage System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # LLM Settings
    LLM_PROVIDER: Literal["mock", "gemini", "openai", "anthropic", "ollama"] = "mock"
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    
    LLM_MODEL: str = "gemini-2.5-pro"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 4096
    
    # Correlation Engine Settings
    CORRELATION_TIME_WINDOW_MINUTES: int = 30
    CORRELATION_MAX_GRAPH_HOPS: int = 2
    MIN_ALERTS_PER_INCIDENT: int = 1
    
    # Malware & Artifact Analysis Settings
    ENTROPY_HIGH_THRESHOLD: float = 7.2
    MAX_FILE_SIZE_BYTES: int = 25 * 1024 * 1024  # 25 MB
    ENABLE_HEURISTIC_YARA: bool = True
    
    # Paths
    DATASETS_DIR: Path = BASE_DIR / "datasets" / "samples"
    STATIC_DIR: Path = BASE_DIR / "server" / "static"
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
