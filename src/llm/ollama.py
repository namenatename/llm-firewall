import httpx
from config import settings

class Ollama:
    def __init__(self):
        self.base_url = settings.llm_base_url
        self.model = settings.llm_model
    
    async def status_check(self) -> bool:
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(f"{self.base_url}/api/tags")
                models = [m["name"] for m in response.json()["models"]]
                if self.model not in models:
                    raise RuntimeError(f"Model '{self.model}' not found in Ollama model list.")
                return True
        except httpx.ConnectError:
            raise RuntimeError("Model unreachable.")

    async def prompt(self, user_input: str) -> str:
        with open("src/llm/agentic_assistant.txt", "r") as f:
            instructions = f.read()
        payload = {
            "model": self.model,
            "prompt": f"{instructions}\nUser: {user_input}",
            "stream": False
        }
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=30.0
                )
                return response.json()["response"]
        except httpx.ConnectError:
            raise RuntimeError(f"Model '{self.model}' not reached.")