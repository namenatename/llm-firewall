# LLM Firewall 

A Python-based prompt injection firewall that intercepts incoming LLM queries, scans inputs against a signature registry containing 5 threat categories, and forwards sanitized requests to a locally hosted Ollama/Mistral backend, which takes the persona of an agentic clothes store shopping assistant!

## Features

* Regex scanning of user inputs against a signature registry mapped to OWASP Top 10 LLM and MITRE ATLAS, with ReDoS protection via SIGALRM timeout

* Source-weighted scoring system that adjusts threat severity based on input origin, with SOFT/HARD threat level classification

* Signature Registry featuring 9 active detection signatures across 5 threat categories: Jailbreak, Prompt Leakage, Context Hijack, Tool Abuse, and Obfuscation

* JSONL audit logging of every scanned request including verdict, risk score, matched rules, flagged categories, and input preview

* Async Mistral LLM integration with startup model validation, system prompt instruction via `agentic_assistant.txt`, and firewall verdicts to generalize Ollama's response to malicious indicators
    * **Agentic Assistant**: clothing boutique assistant demonstrating real-world agentic e-commerce attack surface, with behavioral guidelines and injection awareness

## Threat Detection Coverage

| Category | Rules | Threat Level | OWASP | MITRE ATLAS | Description |
|---|---|---|---|---|---|
| Jailbreak | JB-001, JB-002, JB-003 | HARD | LLM01 | AML.T0054 | Detects direct instruction overrides, system prompt retrieval attempts, and persona switching used to bypass assistant behavioral constraints |
| Prompt Leakage | PL-001 | SOFT | LLM06 | AML.T0056 | Flags attempts to extract session history or user data from the model's context window |
| Context Hijack | CH-001, CH-002 | HARD | LLM01 | AML.T0080, AML.T0051 | Identifies memory poisoning and thread injection patterns that manipulate the model's prior context to alter behavior |
| Tool Abuse | TA-001 | HARD | LLM03 | AML.T0053 | Catches explicit tool invocation attempts targeting agentic backends — script execution, SQL tool calls, and API invocations |
| Obfuscation | OB-001, OB-002 | SOFT / HARD | LLM01 | AML.T0054 | Detects Base64 encoded payloads and explicit encoding requests used to evade pattern-based detection |

## Demoing The Firewall: One-Stop-Shop!

The firewall's verdict response can be tested through an online clothes store assistant with a preset 10-item inventory found in `agentic_assistant.txt`. The assistant handles product questions, sizing, and recommendations while rejecting off-topic or adversarial inputs

Attack scenarios protected by the signature regsitry include:

* Direct prompt injection attempting to override assistant instructions

* Persona switching to bypass behavioral guidelines

* Context hijacking via memory poisoning

* Tool invocation abuse targeting the agentic backend

* Base64 obfuscation to evade pattern detection

## Requirements

* Python 3.11+
* Ollama installed and running locally
* Mistral model pulled via Ollama

## Setup

```bash
# Clone the repo
git clone https://github.com/namenatename/llm-firewall.git
cd llm-firewall

# Create/activate .venv
python -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Pull Mistral model
ollama pull mistral

# Run the firewall
python main.py
```

## Usage

Startup for Ollama before running the firewall (if not already active from startup):

```bash
# Activate .venv
source .venv/bin/activate

# Start Ollama
ollama serve

# Start main.py for CLI user input and Ollama response
python main.py
```

## Output

* Each request is logged to `logs/firewall.jsonl` by default
* The structure of each log entry is as follows:

```json
{"timestamp": "2026-06-27T18:00:00+00:00", 
"verdict": "BLOCKED", 
"risk_score": 50, 
"matched_rules": ["JB-001"], 
"flagged_categories": ["jailbreak"], 
"input_preview": "ignore previous instructions and...", 
"source": "user"
}

{"timestamp": "2026-06-27T18:01:00+00:00", 
"verdict": "CLEAN", 
"risk_score": 0, 
"matched_rules": [],
"flagged_categories": [], 
"input_preview": "do you have blue shirts in size...", 
"source": "user"
}
```

## Future Features

* FastAPI HTTP backend for production deployment (working on this right now!)

* Additional signature coverage for indirect injection and data exfiltration
    * Suggestions/PRs would be helpful! :)

* OpenAI/Anthropic backend support via additional classes/base class structure

## Structure

```
llm-firewall/
    logs/                          # JSONL audit trail
    src/
        firewall/
            logger.py              # Produces JSONL audit logs
            prompt_validation.py   # Ingest layer
            rules.py               # Signature registry and threat rules
            semantic_guidelines.py # Semantic similarity detection (pending)
        llm/
            agentic_assistant.txt  # One-Stop-Shop! agent instructions
            ollama.py              # Async Ollama client with status check
    config.py                      # Settings
    main.py                        # CLI usage
    api.py                         # FastAPI (soon!)
    requirements.txt
```
