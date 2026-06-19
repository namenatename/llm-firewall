# Config settings for Ollama integration

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

# Settings for BaseSettings and type annotations
class Settings(BaseSettings):
     """Flat class structure used for accessibility and local integration with other files"""
     model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8")
     
     # LLM settings
     llm_backend: str = Field(default="ollama")
     llm_model: str = Field(default="mistral")
     llm_base_url: str = Field(default="http://localhost:11434")

     # Firewall settings
     risk_score_threshold: int = Field(default=50, ge=0, le=100)
     max_input_length: int = Field(default=3000, ge=1) # character cap for LLM query
     regex_timeout_seconds: float = Field(default=0.5, gt=0) # limit to reduce latency

     # Logging fields
     log_file_path: str = Field(default="logs/firewall.jsonl")
     log_level: str = Field(default="DEBUG")

# Instantiation of class prevents module misconfig
settings = Settings()

