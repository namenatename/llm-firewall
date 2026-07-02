from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
     model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8")
     
     # LLM settings
     llm_backend: str = Field(default="ollama")
     llm_model: str = Field(default="mistral:latest")
     llm_base_url: str = Field(default="http://localhost:11434")

     # Firewall settings
     risk_score_threshold: int = Field(default=50, ge=0, le=100)
     max_input_length: int = Field(default=3000, ge=1)

     # Logging fields
     log_file_path: str = Field(default="logs/firewall.jsonl")
     log_level: str = Field(default="DEBUG")

settings = Settings()

