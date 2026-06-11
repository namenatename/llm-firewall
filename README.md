# Prompt Injection Firewall

## Overview

A Python-based prompt injection firewall that analyzes incoming LLM queries for common injection patterns, scores against attack signatures, and either blocks the query or forwards a sanitized request that is pushed to Ollama/Mistral backend for inference and response