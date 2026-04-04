"""Shared HTTP client for calling existing Vercel API endpoints."""
from __future__ import annotations
import asyncio
import os
import httpx

class ToolError(Exception):
    def __init__(self, code: str, message: str, retryable: bool) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable

def gatra_client(timeout: int | None = None) -> httpx.AsyncClient:
    timeout = timeout or int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30"))
    base_url = os.getenv("WORLDMONITOR_API_URL", "https://worldmonitor-gatra.vercel.app")
    api_key = os.getenv("GATRA_API_KEY", "")
    return httpx.AsyncClient(
        base_url=base_url,
        headers={
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "GATRA-Agent/1.0 (SOC Pipeline)",
        },
        timeout=httpx.Timeout(timeout),
    )

async def make_request(path: str, *, method: str = "GET", params: dict | None = None,
    json_body: dict | None = None, timeout: int | None = None, max_retries: int = 3) -> dict:
    backoff_delays = [1, 2, 4]
    last_error: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            async with gatra_client(timeout) as client:
                response = await client.request(method, path, params=params, json=json_body)
                if response.status_code >= 500:
                    raise ToolError(code=f"HTTP_{response.status_code}",
                        message=f"Server error from {path}: {response.status_code}", retryable=True)
                if response.status_code >= 400:
                    raise ToolError(code=f"HTTP_{response.status_code}",
                        message=f"Client error from {path}: {response.status_code} — {response.text[:200]}", retryable=False)
                return response.json()
        except ToolError as e:
            if not e.retryable or attempt >= max_retries:
                raise
            last_error = e
        except (httpx.TimeoutException, httpx.ConnectError) as e:
            last_error = e
            if attempt >= max_retries:
                raise ToolError(code="TIMEOUT",
                    message=f"Request to {path} failed after {max_retries + 1} attempts: {e}", retryable=True) from e
        if attempt < max_retries:
            delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
            await asyncio.sleep(delay)
    raise ToolError(code="EXHAUSTED", message=f"All retries exhausted for {path}", retryable=True)
