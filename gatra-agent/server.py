"""GATRA Agent FastAPI server."""
from __future__ import annotations

import os
import uuid

from ag_ui_langgraph import add_langgraph_fastapi_endpoint
from copilotkit import LangGraphAGUIAgent
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from agent.auth import TokenError, resolve_effective_mode, validate_service_token
from agent.graph import build_graph

# ---------------------------------------------------------------------------
# Public paths that skip JWT validation
# ---------------------------------------------------------------------------
_PUBLIC_PREFIXES = {"/health", "/ready", "/dependencies", "/docs", "/openapi.json"}


class ServiceTokenMiddleware(BaseHTTPMiddleware):
    """Validate GATRA service tokens on every non-public request."""

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths and OPTIONS pre-flight
        if request.method == "OPTIONS":
            return await call_next(request)
        for prefix in _PUBLIC_PREFIXES:
            if request.url.path == prefix or request.url.path.startswith(prefix + "/"):
                return await call_next(request)

        secret = os.environ.get("AGENT_SERVICE_SECRET", "")
        if not secret:
            return JSONResponse(
                status_code=500,
                content={"detail": "AGENT_SERVICE_SECRET is not configured"},
            )

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or malformed Authorization header"},
            )

        token = auth_header[len("Bearer "):]
        try:
            claims = validate_service_token(
                token, secret=secret, expected_aud="gatra-agent"
            )
        except TokenError as exc:
            msg = str(exc)
            if "audience" in msg:
                return JSONResponse(status_code=403, content={"detail": msg})
            # expired / malformed / missing claims → 401
            return JSONResponse(status_code=401, content={"detail": msg})

        # Route-scope check
        route_scope: list[str] = claims.get("route_scope", [])
        if not any(
            request.url.path == scope or request.url.path.startswith(scope.rstrip("/") + "/")
            for scope in route_scope
        ):
            return JSONResponse(
                status_code=403,
                content={"detail": f"Token route_scope does not cover {request.url.path}"},
            )

        # Resolve effective mode and store state for downstream graph nodes
        effective_mode = resolve_effective_mode(
            source=claims.get("source", ""),
            requested_mode=claims.get("requested_mode"),
        )
        request.state.claims = claims
        request.state.effective_mode = effective_mode
        request.state.rbac_ceiling = claims.get("role_ceiling", "analyst")
        request.state.trace_id = claims.get("jti", str(uuid.uuid4()))

        return await call_next(request)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="GATRA Agent", version="0.1.0")

origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    os.environ.get("SOC_SITE_ORIGIN", "https://soc.gatra.ai"),
    os.environ.get("COPILOT_ORIGIN", "https://console.soc.gatra.ai"),
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(ServiceTokenMiddleware)

graph = build_graph()

add_langgraph_fastapi_endpoint(
    app=app,
    agent=LangGraphAGUIAgent(
        name="gatra_soc",
        description="GATRA SOC analyst agent",
        graph=graph,
    ),
    path="/",
)


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def ready() -> dict:
    checks: dict = {"graph": graph is not None}
    try:
        from agent.llm import get_llm
        get_llm()
        checks["llm"] = True
    except Exception as exc:
        checks["llm"] = False
        checks["llm_error"] = str(exc)
    all_ready = all(v for k, v in checks.items() if not k.endswith("_error"))
    return {"status": "ready" if all_ready else "not_ready", "checks": checks}


@app.get("/dependencies")
async def dependencies() -> dict:
    import httpx

    base_url = os.getenv("WORLDMONITOR_API_URL", "https://worldmonitor-gatra.vercel.app")
    endpoints = ["/api/gatra-data", "/api/ioc-lookup", "/api/cisa-kev", "/api/threat-feeds"]
    results: dict = {}
    async with httpx.AsyncClient(base_url=base_url, timeout=5.0) as client:
        for ep in endpoints:
            try:
                resp = await client.head(ep)
                results[ep] = {"status": resp.status_code, "healthy": resp.status_code < 500}
            except Exception as exc:
                results[ep] = {"status": "error", "healthy": False, "error": str(exc)}
    return {"dependencies": results}
