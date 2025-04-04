from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    app_name: str = "Security Scanner API"
    debug: bool = True

    class Config:
        env_file = ".env" 