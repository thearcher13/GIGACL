from pathlib import Path

from pydantic_settings import BaseSettings

# Absolute, so the file is found wherever the process was started from.
# start.sh runs uvicorn with the working directory set to backend/, so a
# relative "env_file" silently missed the project-root .env — and a secret
# that cannot be read back is a secret that gets regenerated on every boot,
# taking every stored switch password with it.
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    # No usable default: a real key is generated and persisted on first run.
    # Anything that ships in the repository is public by definition.
    SECRET_KEY: str = ""
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    DATABASE_URL: str = "sqlite:///./giga_acl.db"

    class Config:
        env_file = str(ENV_PATH)
        extra = "ignore"


settings = Settings()
