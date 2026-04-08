from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    """
    App config.
    
    FUTURE: Add agent config here (reasoning depth, tool list, memory backend)
    """
    # API Keys
    anthropic_api_key: str
    
    # Server
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    frontend_url: str = "http://localhost:3000"
    
    # Database
    database_url: str = "sqlite:///./database.db"
    
    # LLM
    llm_model: str = "claude-3-5-sonnet-20241022"
    llm_max_tokens: int = 500
    llm_temperature: float = 0.3
    
    class Config:
        env_file = ".env"
        case_sensitive = False

@lru_cache()
def get_settings():
    return Settings()