from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "CampaignX AI"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Execution Mode
    MODE: str = "online"  # 'offline' or 'online'
    APP_ENV: str = "development"
    DEBUG: bool = True
    
    # Server configuration
    BACKEND_HOST: str = "0.0.0.0"
    BACKEND_PORT: int = 8001
    FRONTEND_URL: str = "http://localhost:5173"
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
        "http://localhost:8001",
    ]
    
    # Database & Cache
    DATABASE_URL: str = "sqlite:///./campaignx.db"
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    
    # Security & Auth
    JWT_SECRET: str = "super_secret_campaignx_jwt_key_change_in_production_32bytes_minimum"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours
    PII_HMAC_KEY: str = "campaignx_pii_hmac_secret_key_32bytes_min"
    
    # AI Threat Intelligence & Investigation Providers
    GEMINI_API_KEY: Optional[str] = None
    OPENROUTER_API_KEY: Optional[str] = None
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    THREATFUSION_API_KEY: Optional[str] = None
    THREATFUSION_BASE_URL: str = "https://api.threatfusion.ai"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def is_offline(self) -> bool:
        return self.MODE.lower() == "offline"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
