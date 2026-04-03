"""GATRA Agent FastAPI server."""
from __future__ import annotations

from ag_ui_langgraph import add_langgraph_fastapi_endpoint
from copilotkit import LangGraphAGUIAgent
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agent.graph import build_graph

app = FastAPI(title="GATRA Agent", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "http://127.0.0.1:3000", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
    import os

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
