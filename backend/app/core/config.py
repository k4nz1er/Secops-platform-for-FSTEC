from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "SecOps Vulnerability & Threat Management Platform"
    CORS_ORIGINS: List[str] = ["http://localhost", "http://localhost:3000", "http://localhost:80"]

    DB_USER: str = "secops_admin"
    DB_PASS: str = "StrongSecOpsPass2026!"
    DB_NAME: str = "secops_db"
    DB_HOST: str = "postgres"
    DB_PORT: int = 5432

    REDIS_URL: str = "redis://redis:6379/0"
    RABBITMQ_URL: str = "amqp://secops:RabbitPass2026!@rabbitmq:5672//"

    KEYCLOAK_URL: str = "http://keycloak:8080"
    KEYCLOAK_REALM: str = "secops"
    KEYCLOAK_CLIENT_ID: str = "secops-frontend"

    SECRET_KEY: str = "ChangeMeToRandom64CharHexStringForProduction2026"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def DATABASE_URL(self) -> str:
        return f"postgresql://{self.DB_USER}:{self.DB_PASS}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"


settings = Settings()
