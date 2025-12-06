from pydantic import BaseSettings, AnyHttpUrl
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str = "Secure Login System"
    PROJECT_VERSION: str = "0.1.0"
    DATABASE_URL: str
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    ALGORITHM: str = "HS256"
    BACKEND_CORS_ORIGINS: List[AnyHttpUrl] = []

    class Config:
        env_file = "../../.env"

settings = Settings()
