from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Honeypot Analyzer"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database
    DATABASE_URL: str = "sqlite:///./honeypot.db"

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Honeypot Connections
    T_POT_API_URL: Optional[str] = None
    COWRIE_API_URL: Optional[str] = None

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"

    # File Upload
    MAX_UPLOAD_SIZE: int = 100 * 1024 * 1024  # 100MB
    ALLOWED_EXTENSIONS: list = [".json", ".log", ".txt"]

    class Config:
        env_file = ".env"

settings = Settings()