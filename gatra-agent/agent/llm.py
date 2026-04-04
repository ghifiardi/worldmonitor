"""LLM provider factory with configurable fallback."""
from __future__ import annotations
import os
from langchain_core.language_models import BaseChatModel

class LLMProviderUnavailableError(Exception):
    """Retryable provider errors — timeouts, rate limits, temporary outages."""

def get_llm(provider: str | None = None, timeout: int | None = None) -> BaseChatModel:
    provider = provider or os.getenv("LLM_PROVIDER", "anthropic")
    timeout = timeout or int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    match provider:
        case "anthropic":
            from langchain_anthropic import ChatAnthropic
            return ChatAnthropic(model="claude-sonnet-4-20250514", timeout=timeout)
        case "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(model="gpt-4o", timeout=timeout)
        case "groq":
            from langchain_groq import ChatGroq
            return ChatGroq(model="llama-3.3-70b-versatile", timeout=timeout)
        case _:
            raise ValueError(f"Unsupported LLM_PROVIDER: {provider}")

def get_llm_with_fallback(timeout: int | None = None) -> BaseChatModel:
    try:
        return get_llm(timeout=timeout)
    except LLMProviderUnavailableError:
        fallback = os.getenv("LLM_FALLBACK_PROVIDER")
        if fallback:
            return get_llm(fallback, timeout=timeout)
        raise
