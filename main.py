import asyncio
from src.llm.ollama import Ollama
from src.firewall.prompt_validation import scan_input
from src.firewall.logger import log_request

ollama = Ollama()

async def main():
    try:
        await ollama.status_check()
    except RuntimeError as e:
        print(f"Startup failed: {e}")
        return

    print("Welcome to One-Stop-Shop! Type 'exit' to end the conversation.\n")

    user_input = input("You: ").strip()

    while user_input.lower() != "exit":
        if user_input:
            result = scan_input(user_input, source="user")
            log_request(result)

            print("\nAssistant: ", end="", flush=True)
            await ollama.prompt(
                f"[Firewall status: {result.verdict.value}]\nUser: {user_input}"
            )
            print()

        user_input = input("You: ").strip()

    result = scan_input(user_input, source="user")
    log_request(result)
    print("\nAssistant: ", end="", flush=True)
    await ollama.prompt(
        f"[Firewall status: {result.verdict.value}]\nUser: {user_input}"
    )
    print()

if __name__ == "__main__":
    asyncio.run(main())
