import pytest
from agent.llm import LLMProviderUnavailableError, get_llm

def test_get_llm_anthropic(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    llm = get_llm("anthropic")
    assert llm is not None

def test_get_llm_openai(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    llm = get_llm("openai")
    assert llm is not None

def test_get_llm_groq(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    llm = get_llm("groq")
    assert llm is not None

def test_get_llm_invalid_provider():
    with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
        get_llm("invalid")

def test_get_llm_defaults_to_env(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    llm = get_llm()
    assert llm is not None
