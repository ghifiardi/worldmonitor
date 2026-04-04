import httpx
import pytest
from unittest.mock import AsyncMock, patch
from agent.tools.client import ToolError, make_request

@pytest.fixture
def base_url(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")
    return "https://test.example.com"

async def test_make_request_success(httpx_mock, base_url):
    httpx_mock.add_response(url="https://test.example.com/api/gatra-data", json={"alerts": []})
    result = await make_request("/api/gatra-data")
    assert result == {"alerts": []}

async def test_make_request_timeout_retries(httpx_mock, base_url):
    httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    httpx_mock.add_response(url="https://test.example.com/api/gatra-data", json={"ok": True})
    with patch("agent.tools.client.asyncio.sleep", new_callable=AsyncMock):
        result = await make_request("/api/gatra-data", max_retries=3)
    assert result == {"ok": True}

async def test_make_request_all_retries_exhausted(httpx_mock, base_url):
    for _ in range(4):
        httpx_mock.add_exception(httpx.ReadTimeout("timeout"))
    with patch("agent.tools.client.asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(ToolError) as exc_info:
            await make_request("/api/gatra-data", max_retries=3)
    assert exc_info.value.retryable is True

async def test_make_request_4xx_not_retryable(httpx_mock, base_url):
    httpx_mock.add_response(url="https://test.example.com/api/gatra-data", status_code=401, json={"error": "Unauthorized"})
    with pytest.raises(ToolError) as exc_info:
        await make_request("/api/gatra-data")
    assert exc_info.value.retryable is False
    assert exc_info.value.code == "HTTP_401"
