import httpx
import json
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
            "stream": True
        }
        try:
            # Handles token stream for Ollama outputs within the CLI
            full_response = ""
            async with httpx.AsyncClient() as client:
                async with client.stream("POST", f"{self.base_url}/api/generate", json=payload, timeout=30.0) as response:
                    async for line in response.aiter_lines():
                        if line:
                            chunk = json.loads(line)
                            token = chunk.get("response", "")
                            print(token, end="", flush=True)
                            full_response += token
                            if chunk.get("done"):
                                break
            print()
            return full_response
        except httpx.ConnectError:
            raise RuntimeError(f"Model '{self.model}' not reached.")