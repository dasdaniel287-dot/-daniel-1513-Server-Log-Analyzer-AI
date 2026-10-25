"""
Application Configuration & Settings
Safe bounds, threshold defaults, and environment parsing.
"""

import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    APP_NAME: str = "Server Log Analyzer AI"
    APP_VERSION: str = "2026.1.0-LTS"
    DEBUG: bool = False
    
    HOST: str = "0.0.0.0"
    PORT: int = int(os.getenv("PORT", "3000"))
    
    # Upload limits
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB
    CHUNK_SIZE_BYTES: int = 64 * 1024              # 64 KB
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./data/logs.db")
    
    # External AI
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    
    # Security Invariants
    STRICT_SANITIZATION: bool = True
    ALLOW_EXTERNAL_AI_PROCESSING: bool = True
    
    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
