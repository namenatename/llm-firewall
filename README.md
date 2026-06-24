# Prompt Injection Firewall

## Overview

A Python-based prompt injection firewall that analyzes incoming LLM queries for common injection patterns, scores inputs against known attack signatures, and  blocks the query or forwards a sanitized request that is pushed to Ollama/Mistral backend for inference and response.

## Use-cases For This Firewall

This prompt injection firewall has direct compatibility with AI SaaS solutions that implement agentic assistants within web interfaces. The multiple layers of security and request approval (ingest -> semantic -> approval) provides defense and a secures production environments for agentic scenarios, incuding e-commerce, customer support, and tool-based agents

## Key Features

