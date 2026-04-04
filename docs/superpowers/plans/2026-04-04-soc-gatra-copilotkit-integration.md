# CopilotKit Integration into soc.gatra.ai — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate CopilotKit into soc.gatra.ai so it connects to the shared gatra-agent backend in lite mode — full analytical intelligence, no execution capability.

**Architecture:** The gatra-agent LangGraph backend gains a `mode` enum (`full`/`lite`) enforced as an execution invariant. soc.gatra.ai gets an incremental App Router (`app/` alongside `pages/`) with a new `/soc-analyst` page mounting CopilotKit. A signed service token with `source: "soc-site"` forces `effective_mode=lite` server-side. Generative UI components (AlertCard, MitreCard, VulnCard) are copied from gatra-copilot with a LiteModeGuard wrapper.

**Tech Stack:** Python 3.13 (FastAPI, LangGraph, Pydantic), Next.js 14 + App Router (incremental), CopilotKit v1.54, React 18, Tailwind CSS, PyJWT

**Spec:** `docs/superpowers/specs/2026-04-04-soc-gatra-copilotkit-integration-design.md`

**Key Paths:**
- Agent backend: `worldmonitor/gatra-agent/`
- Copilot frontend (source of truth for UI): `worldmonitor/gatra-copilot/`
- soc.gatra.ai: `GitHub/gatra-production/`

---

## Workstream A: Backend Mode System

### Task 1: Add AgentMode enum and mode field to GatraState

**Files:**
- Modify: `worldmonitor/gatra-agent/agent/state.py:124-151`
- Test: `worldmonitor/gatra-agent/tests/test_state.py`

- [ ] **Step 1: Write failing test for AgentMode enum and mode field**

```python
# tests/test_state.py — append to existing file

from agent.state import AgentMode

def test_agent_mode_enum_values():
    assert AgentMode.full == "full"
    assert AgentMode.lite == "lite"

def test_gatra_state_defaults_to_full_mode():
    state = GatraState(messages=[])
    assert state.mode == AgentMode.full

def test_gatra_state_accepts_lite_mode():
    state = GatraState(messages=[], mode=AgentMode.lite)
    assert state.mode == AgentMode.lite

def test_gatra_state_rejects_invalid_mode():
    import pytest
    with pytest.raises(Exception):
        GatraState(messages=[], mode="invalid")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_state.py::test_agent_mode_enum_values -v`
Expected: FAIL — `ImportError: cannot import name 'AgentMode'`

- [ ] **Step 3: Add AgentMode enum and mode field to state.py**

Add before the `GatraState` class (around line 123):

```python
class AgentMode(str, Enum):
    full = "full"
    lite = "lite"
```

Add `Enum` to the imports at the top of `state.py`:

```python
from enum import Enum
```

Add `mode` field to `GatraState` (after `copilotkit` field, around line 128):

```python
mode: AgentMode = AgentMode.full
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_state.py -v`
Expected: All PASS including new mode tests

- [ ] **Step 5: Commit**

```bash
cd worldmonitor/gatra-agent
git add agent/state.py tests/test_state.py
git commit -m "feat(agent): add AgentMode enum and mode field to GatraState"
```

---

### Task 2: Add mode-aware conditional edge to skip RVA in lite mode

**Files:**
- Modify: `worldmonitor/gatra-agent/agent/graph.py:88-102`
- Test: `worldmonitor/gatra-agent/tests/test_graph.py`

- [ ] **Step 1: Write failing test for mode-aware routing**

```python
# tests/test_graph.py — append to existing file

from agent.state import AgentMode

def test_graph_cra_routes_to_rva_in_full_mode():
    """CRA → RVA when mode is full."""
    graph = build_graph()
    # Verify conditional edge exists from CRA
    edges = graph.graph.edges
    # CRA should have a conditional edge, not a direct edge to RVA
    cra_edges = [e for e in edges if e[0] == "cra"]
    assert len(cra_edges) > 0

def test_cra_dispatch_returns_rva_for_full():
    from agent.graph import _cra_dispatch
    from agent.state import GatraState, AgentMode
    state = GatraState(messages=[], mode=AgentMode.full)
    assert _cra_dispatch(state) == "rva"

def test_cra_dispatch_returns_end_for_lite():
    from agent.graph import _cra_dispatch
    from agent.state import GatraState, AgentMode
    state = GatraState(messages=[], mode=AgentMode.lite)
    assert _cra_dispatch(state) == "__end__"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_graph.py::test_cra_dispatch_returns_end_for_lite -v`
Expected: FAIL — `ImportError: cannot import name '_cra_dispatch'`

- [ ] **Step 3: Replace CRA → RVA direct edge with conditional edge**

In `agent/graph.py`, add the dispatch function (after `_taa_dispatch`, around line 45):

```python
def _cra_dispatch(state: GatraState) -> str:
    """Route CRA output: full mode → RVA, lite mode → END."""
    if state.mode == AgentMode.lite:
        return "__end__"
    return "rva"
```

Add import at top of graph.py:

```python
from agent.state import AgentMode
```

Replace the direct edge `graph.add_edge("cra", "rva")` (around line 95) with:

```python
graph.add_conditional_edges("cra", _cra_dispatch, {"rva": "rva", "__end__": "__end__"})
```

- [ ] **Step 4: Run all graph tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_graph.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
cd worldmonitor/gatra-agent
git add agent/graph.py tests/test_graph.py
git commit -m "feat(agent): add mode-aware CRA→RVA conditional edge"
```

---

### Task 3: CRA lite mode — read-only actions, no interrupt

**Files:**
- Modify: `worldmonitor/gatra-agent/agent/nodes/cra.py:131-342`
- Test: `worldmonitor/gatra-agent/tests/test_cra.py`

- [ ] **Step 1: Write failing tests for CRA lite behavior**

```python
# tests/test_cra.py — append to existing file

from agent.state import AgentMode, ProposedAction, GatraState
from agent.nodes.cra import enforce_lite_mode
from copy import deepcopy

def _sample_action() -> ProposedAction:
    return ProposedAction(
        action_id="act-001",
        incident_id="inc-001",
        action_type="block",
        target_type="ip",
        target_value="10.0.0.1",
        severity="HIGH",
        confidence=0.95,
        rationale="Suspicious outbound traffic",
        requires_approval=True,
        status="proposed",
        expires_at="2026-04-04T12:00:00Z",
    )

def test_enforce_lite_mode_marks_all_non_executable():
    actions = [_sample_action(), _sample_action()]
    result = enforce_lite_mode(actions)
    for a in result:
        assert a.executable is False
        assert a.reason == "read-only mode — view in Analyst Console for execution"

def test_enforce_lite_mode_does_not_mutate_originals():
    original = _sample_action()
    original_id = id(original)
    result = enforce_lite_mode([original])
    assert id(result[0]) != original_id

def test_enforce_lite_mode_empty_list():
    assert enforce_lite_mode([]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_cra.py::test_enforce_lite_mode_marks_all_non_executable -v`
Expected: FAIL — `ImportError: cannot import name 'enforce_lite_mode'`

- [ ] **Step 3: Add enforce_lite_mode function and integrate into cra_node**

In `agent/nodes/cra.py`, add the `enforce_lite_mode` function (before `cra_node`, around line 128):

```python
from copy import deepcopy
from agent.state import AgentMode

def enforce_lite_mode(actions: list) -> list:
    """Deep-copy actions and mark all as non-executable for lite mode."""
    result = []
    for action in actions:
        a = deepcopy(action)
        a.executable = False
        a.reason = "read-only mode — view in Analyst Console for execution"
        result.append(a)
    return result
```

Add `executable` and `reason` fields to `ProposedAction` in `agent/state.py` if not present (check first — add after `status` field around line 48):

```python
executable: bool = True
reason: str | None = None
```

In the `cra_node` function (around line 131), add a lite-mode early return after proposed actions are built but before policy evaluation and interrupt logic:

```python
# After building proposed_actions (before policy evaluation, ~line 169)
if state.mode == AgentMode.lite:
    lite_actions = enforce_lite_mode(proposed_actions)
    return {
        "proposed_actions": lite_actions,
        "current_agent": "CRA",
        "pipeline_stage": "responding",
    }
```

- [ ] **Step 4: Run all CRA tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_cra.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
cd worldmonitor/gatra-agent
git add agent/nodes/cra.py agent/state.py tests/test_cra.py
git commit -m "feat(agent): CRA read-only mode — non-executable actions, no interrupt in lite"
```

---

### Task 4: Execution invariant checks in RVA and CLA nodes

**Files:**
- Modify: `worldmonitor/gatra-agent/agent/nodes/rva.py:21`
- Modify: `worldmonitor/gatra-agent/agent/nodes/cla_report.py:21`
- Test: `worldmonitor/gatra-agent/tests/test_mode_invariants.py` (new)

- [ ] **Step 1: Write failing tests for node-level mode invariants**

```python
# tests/test_mode_invariants.py (new file)

from agent.state import AgentMode, GatraState

def test_rva_noop_in_lite_mode():
    """RVA must no-op if accidentally reached in lite mode."""
    from agent.nodes.rva import rva_node
    import asyncio

    state = GatraState(messages=[], mode=AgentMode.lite)
    result = asyncio.run(rva_node(state, config=None))
    # Should return empty/no-op — no vulnerability_context added
    assert result.get("vulnerability_context") is None or result.get("vulnerability_context") == []

def test_cla_no_execution_side_effects_in_lite():
    """CLA must still log but not trigger operational actions in lite mode."""
    from agent.nodes.cla_report import cla_report_node
    import asyncio

    state = GatraState(
        messages=[],
        mode=AgentMode.lite,
        audit_log=[],
    )
    result = asyncio.run(cla_report_node(state, config=None))
    # CLA should still produce audit entries (logging is allowed)
    # but should not produce any executed_actions or operational commands
    assert "executed_actions" not in result or result.get("executed_actions") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_mode_invariants.py::test_rva_noop_in_lite_mode -v`
Expected: FAIL — RVA runs full logic regardless of mode

- [ ] **Step 3: Add mode guards to RVA and CLA nodes**

In `agent/nodes/rva.py`, add at the start of `rva_node` (after line 21):

```python
from agent.state import AgentMode

async def rva_node(state: GatraState, config: RunnableConfig):
    # Execution invariant: lite mode must not run vulnerability assessment
    if state.mode == AgentMode.lite:
        return {"vulnerability_context": [], "current_agent": "RVA", "pipeline_stage": "assessing"}
    # ... existing logic unchanged
```

In `agent/nodes/cla_report.py`, add a guard that skips any operational side effects (the existing CLA only logs, so this is primarily a documented invariant). Add at the start of `cla_report_node` (after line 21):

```python
from agent.state import AgentMode

async def cla_report_node(state: GatraState, config: RunnableConfig):
    # In lite mode: audit logging only, no operational side effects
    # (Current implementation is already audit-only, but this guard
    # makes the invariant explicit for future changes)
    # ... existing logging logic runs in both modes
```

- [ ] **Step 4: Run all mode invariant tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_mode_invariants.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite to verify no regressions**

Run: `cd worldmonitor/gatra-agent && python -m pytest -v`
Expected: All existing tests still PASS

- [ ] **Step 6: Commit**

```bash
cd worldmonitor/gatra-agent
git add agent/nodes/rva.py agent/nodes/cla_report.py tests/test_mode_invariants.py
git commit -m "feat(agent): add execution invariant guards to RVA and CLA for lite mode"
```

---

## Workstream B: Token & Auth

### Task 5: Token minting and validation library

**Files:**
- Create: `worldmonitor/gatra-agent/agent/auth.py`
- Test: `worldmonitor/gatra-agent/tests/test_auth.py` (new)

- [ ] **Step 1: Write failing tests for token creation and validation**

```python
# tests/test_auth.py (new file)

import time
import pytest
from agent.auth import mint_service_token, validate_service_token, TokenError

SECRET = "test-secret-key-at-least-32-chars-long"

def test_mint_token_creates_valid_jwt():
    token = mint_service_token(
        sub="user@gatra.ai",
        iss="soc.gatra.ai",
        aud="gatra-agent",
        source="soc-site",
        role_ceiling="analyst",
        route_scope=["/agent/run"],
        secret=SECRET,
        ttl_seconds=300,
    )
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT has 3 parts

def test_validate_token_returns_claims():
    token = mint_service_token(
        sub="user@gatra.ai",
        iss="soc.gatra.ai",
        aud="gatra-agent",
        source="soc-site",
        role_ceiling="analyst",
        route_scope=["/agent/run"],
        secret=SECRET,
        ttl_seconds=300,
    )
    claims = validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")
    assert claims["sub"] == "user@gatra.ai"
    assert claims["iss"] == "soc.gatra.ai"
    assert claims["source"] == "soc-site"
    assert claims["role_ceiling"] == "analyst"
    assert claims["route_scope"] == ["/agent/run"]

def test_validate_rejects_expired_token():
    token = mint_service_token(
        sub="user@gatra.ai", iss="soc.gatra.ai", aud="gatra-agent",
        source="soc-site", role_ceiling="analyst", route_scope=["/agent/run"],
        secret=SECRET, ttl_seconds=-1,
    )
    with pytest.raises(TokenError, match="expired"):
        validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")

def test_validate_rejects_wrong_audience():
    token = mint_service_token(
        sub="user@gatra.ai", iss="soc.gatra.ai", aud="wrong-aud",
        source="soc-site", role_ceiling="analyst", route_scope=["/agent/run"],
        secret=SECRET, ttl_seconds=300,
    )
    with pytest.raises(TokenError, match="audience"):
        validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")

def test_validate_rejects_wrong_secret():
    token = mint_service_token(
        sub="user@gatra.ai", iss="soc.gatra.ai", aud="gatra-agent",
        source="soc-site", role_ceiling="analyst", route_scope=["/agent/run"],
        secret=SECRET, ttl_seconds=300,
    )
    with pytest.raises(TokenError, match="invalid"):
        validate_service_token(token, secret="wrong-secret-that-is-also-long-enough", expected_aud="gatra-agent")

def test_validate_rejects_missing_aud():
    """Token without aud claim should be rejected."""
    import jwt
    payload = {"sub": "user@gatra.ai", "iss": "soc.gatra.ai", "exp": time.time() + 300}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="missing"):
        validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")

def test_validate_rejects_missing_iss():
    import jwt
    payload = {"sub": "user@gatra.ai", "aud": "gatra-agent", "exp": time.time() + 300}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="missing"):
        validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")

def test_validate_rejects_missing_route_scope():
    import jwt
    payload = {"sub": "u", "iss": "soc.gatra.ai", "aud": "gatra-agent",
               "source": "soc-site", "role_ceiling": "analyst", "exp": time.time() + 300}
    token = jwt.encode(payload, SECRET, algorithm="HS256")
    with pytest.raises(TokenError, match="missing"):
        validate_service_token(token, secret=SECRET, expected_aud="gatra-agent")

def test_source_soc_site_forces_lite_mode():
    from agent.auth import resolve_effective_mode
    assert resolve_effective_mode(source="soc-site", requested_mode="full") == "lite"

def test_source_copilot_allows_full_mode():
    from agent.auth import resolve_effective_mode
    assert resolve_effective_mode(source="copilot", requested_mode="full") == "full"

def test_source_copilot_defaults_to_full():
    from agent.auth import resolve_effective_mode
    assert resolve_effective_mode(source="copilot", requested_mode=None) == "full"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_auth.py::test_mint_token_creates_valid_jwt -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent.auth'`

- [ ] **Step 3: Install PyJWT dependency**

Run: `cd worldmonitor/gatra-agent && uv add PyJWT`

- [ ] **Step 4: Implement auth module**

```python
# agent/auth.py (new file)

import time
import jwt


class TokenError(Exception):
    """Raised when a service token is invalid."""
    pass


REQUIRED_CLAIMS = {"sub", "iss", "aud", "exp", "source", "role_ceiling", "route_scope"}


def mint_service_token(
    *,
    sub: str,
    iss: str,
    aud: str,
    source: str,
    role_ceiling: str,
    route_scope: list[str],
    secret: str,
    ttl_seconds: int,
) -> str:
    """Create a signed JWT service token."""
    now = time.time()
    payload = {
        "sub": sub,
        "iss": iss,
        "aud": aud,
        "source": source,
        "role_ceiling": role_ceiling,
        "route_scope": route_scope,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_service_token(
    token: str,
    *,
    secret: str,
    expected_aud: str,
) -> dict:
    """Validate and decode a service token. Raises TokenError on failure."""
    try:
        claims = jwt.decode(token, secret, algorithms=["HS256"], audience=expected_aud)
    except jwt.ExpiredSignatureError:
        raise TokenError("token expired")
    except jwt.InvalidAudienceError:
        raise TokenError("invalid audience")
    except jwt.DecodeError:
        raise TokenError("invalid token signature")
    except jwt.InvalidTokenError as e:
        raise TokenError(f"invalid token: {e}")

    missing = REQUIRED_CLAIMS - set(claims.keys())
    if missing:
        raise TokenError(f"missing required claims: {missing}")

    return claims


def resolve_effective_mode(*, source: str, requested_mode: str | None) -> str:
    """Determine effective_mode from token source. soc-site always forces lite."""
    if source == "soc-site":
        return "lite"
    return requested_mode or "full"
```

- [ ] **Step 5: Run all auth tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_auth.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
cd worldmonitor/gatra-agent
git add agent/auth.py tests/test_auth.py pyproject.toml uv.lock
git commit -m "feat(agent): add JWT service token minting, validation, and mode resolution"
```

---

### Task 6: Token validation middleware in FastAPI

**Files:**
- Modify: `worldmonitor/gatra-agent/server.py:11-31`
- Test: `worldmonitor/gatra-agent/tests/test_server_auth.py` (new)

- [ ] **Step 1: Write failing tests for middleware behavior**

```python
# tests/test_server_auth.py (new file)

import os
import pytest
from fastapi.testclient import TestClient

os.environ["AGENT_SERVICE_SECRET"] = "test-secret-key-at-least-32-chars-long"

from server import app
from agent.auth import mint_service_token

SECRET = "test-secret-key-at-least-32-chars-long"

client = TestClient(app)

def _make_token(source="soc-site", aud="gatra-agent", role_ceiling="analyst", ttl=300, route_scope=None):
    return mint_service_token(
        sub="test@gatra.ai", iss="soc.gatra.ai", aud=aud,
        source=source, role_ceiling=role_ceiling,
        route_scope=route_scope or ["/agent/run"],
        secret=SECRET, ttl_seconds=ttl,
    )

def test_health_does_not_require_auth():
    resp = client.get("/health")
    assert resp.status_code == 200

def test_agent_endpoint_rejects_missing_token():
    resp = client.post("/agent/run", json={"message": "test"})
    assert resp.status_code == 401

def test_agent_endpoint_rejects_expired_token():
    token = _make_token(ttl=-1)
    resp = client.post("/agent/run", json={"message": "test"},
                       headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401

def test_agent_endpoint_rejects_wrong_audience():
    token = _make_token(aud="wrong")
    resp = client.post("/agent/run", json={"message": "test"},
                       headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403

def test_agent_endpoint_accepts_valid_token():
    token = _make_token()
    resp = client.post("/agent/run", json={"message": "test"},
                       headers={"Authorization": f"Bearer {token}"})
    # May get a different error (agent not fully running), but NOT 401/403
    assert resp.status_code not in (401, 403)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_server_auth.py::test_agent_endpoint_rejects_missing_token -v`
Expected: FAIL — no auth middleware, request goes through

- [ ] **Step 3: Add token validation middleware to server.py**

In `server.py`, add the middleware after CORS setup (around line 19):

```python
import os
import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from agent.auth import validate_service_token, resolve_effective_mode, TokenError

logger = logging.getLogger("gatra-agent")

# Paths that do not require authentication
PUBLIC_PATHS = {"/health", "/ready", "/dependencies", "/docs", "/openapi.json"}

class ServiceTokenMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in PUBLIC_PATHS or request.method == "OPTIONS":
            return await call_next(request)

        secret = os.environ.get("AGENT_SERVICE_SECRET")
        if not secret:
            logger.error("AGENT_SERVICE_SECRET not configured")
            return JSONResponse({"error": "server configuration error"}, status_code=500)

        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return JSONResponse({"error": "missing or invalid authorization"}, status_code=401)

        token = auth_header[7:]
        try:
            claims = validate_service_token(token, secret=secret, expected_aud="gatra-agent")
        except TokenError as e:
            status = 403 if "audience" in str(e) else 401
            logger.warning("Token rejected: %s", e)
            return JSONResponse({"error": "unauthorized"}, status_code=status)

        # Check route_scope
        if request.url.path not in claims.get("route_scope", []):
            logger.warning("Route scope mismatch: %s not in %s", request.url.path, claims["route_scope"])
            return JSONResponse({"error": "forbidden"}, status_code=403)

        # Resolve effective mode
        requested_mode = request.headers.get("X-Requested-Mode")
        effective_mode = resolve_effective_mode(
            source=claims["source"],
            requested_mode=requested_mode,
        )

        # Store in request state for downstream use
        request.state.claims = claims
        request.state.effective_mode = effective_mode
        request.state.rbac_ceiling = claims["role_ceiling"]
        request.state.trace_id = request.headers.get("X-Trace-ID", "")

        logger.info(
            "Request authenticated",
            extra={
                "sub": claims["sub"],
                "source": claims["source"],
                "requested_mode": requested_mode,
                "effective_mode": effective_mode,
                "trace_id": request.state.trace_id,
            },
        )

        return await call_next(request)

app.add_middleware(ServiceTokenMiddleware)
```

Add soc.gatra.ai to CORS origins (update the existing CORS middleware origins list):

```python
origins = [
    "http://localhost:3000",
    "http://localhost:3001",
    os.environ.get("SOC_SITE_ORIGIN", "https://soc.gatra.ai"),
    os.environ.get("COPILOT_ORIGIN", "https://console.soc.gatra.ai"),
]
```

- [ ] **Step 4: Run all server auth tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_server_auth.py -v`
Expected: All PASS

- [ ] **Step 5: Run full backend test suite**

Run: `cd worldmonitor/gatra-agent && python -m pytest -v`
Expected: All PASS (existing tests may need AGENT_SERVICE_SECRET set or use public paths)

- [ ] **Step 6: Commit**

```bash
cd worldmonitor/gatra-agent
git add server.py tests/test_server_auth.py
git commit -m "feat(agent): add JWT service token validation middleware with mode resolution"
```

---

### Task 7: Integration test — lite mode end-to-end graph run

**Files:**
- Create: `worldmonitor/gatra-agent/tests/test_integration_lite.py`

- [ ] **Step 1: Write integration test for full lite-mode graph run**

```python
# tests/test_integration_lite.py (new file)

import asyncio
import pytest
from unittest.mock import AsyncMock, patch
from agent.graph import build_graph
from agent.state import GatraState, AgentMode, Alert

def _sample_alert():
    return Alert(
        id="alert-001",
        severity="HIGH",
        mitre_id="T1566.001",
        mitre_name="Spearphishing Attachment",
        description="Suspicious email with macro-enabled attachment",
        confidence=0.92,
        timestamp="2026-04-04T10:00:00Z",
        agent="ADA",
    )

@pytest.mark.asyncio
@patch("agent.nodes.ada.fetch_alerts", new_callable=AsyncMock)
@patch("agent.nodes.taa.get_llm")
@patch("agent.nodes.cra.get_llm")
async def test_lite_mode_graph_skips_rva_and_returns_readonly_actions(
    mock_cra_llm, mock_taa_llm, mock_fetch_alerts
):
    """Full graph run in lite mode: ADA→TAA→CRA(read-only)→END, no RVA."""
    mock_fetch_alerts.return_value = [_sample_alert()]

    # Mock LLM responses for TAA and CRA
    mock_taa_llm.return_value.ainvoke = AsyncMock(return_value=type("Msg", (), {
        "content": '{"kill_chain_phase": "delivery", "actor_attribution": "UNC2452", "confidence": 0.85}'
    })())
    mock_cra_llm.return_value.ainvoke = AsyncMock(return_value=type("Msg", (), {
        "content": '{"action_type": "block", "target_type": "ip", "target_value": "10.0.0.1", "rationale": "Block C2"}'
    })())

    graph = build_graph()
    initial_state = GatraState(
        messages=[{"role": "user", "content": "Analyze alert alert-001"}],
        mode=AgentMode.lite,
        alerts=[_sample_alert()],
    )

    config = {"configurable": {"thread_id": "test-lite-001"}}
    result = await graph.ainvoke(initial_state, config)

    # Verify CRA produced actions but all are non-executable
    for action in result.get("proposed_actions", []):
        assert action.executable is False
        assert "read-only" in action.reason

    # Verify RVA was NOT executed (no vulnerability_context)
    assert result.get("vulnerability_context") is None or result.get("vulnerability_context") == []

    # Verify nodes_executed does not include RVA
    # (Check pipeline_stage or audit_log for node execution evidence)

@pytest.mark.asyncio
async def test_mode_override_soc_site_token_forces_lite():
    """Client sends mode=full with soc-site token → effective_mode=lite."""
    from agent.auth import resolve_effective_mode
    effective = resolve_effective_mode(source="soc-site", requested_mode="full")
    assert effective == "lite"

@pytest.mark.asyncio
async def test_copilot_token_allows_full_mode():
    """Copilot token retains full mode — regression test."""
    from agent.auth import resolve_effective_mode
    effective = resolve_effective_mode(source="copilot", requested_mode="full")
    assert effective == "full"
```

- [ ] **Step 2: Run integration tests**

Run: `cd worldmonitor/gatra-agent && python -m pytest tests/test_integration_lite.py -v`
Expected: All PASS (may need to adjust mocks based on actual node signatures)

- [ ] **Step 3: Commit**

```bash
cd worldmonitor/gatra-agent
git add tests/test_integration_lite.py
git commit -m "test(agent): add integration tests for lite-mode graph execution"
```

---

## Workstream C: Frontend Integration (soc.gatra.ai)

### Task 8: Install CopilotKit dependencies and set up App Router

**Files:**
- Modify: `GitHub/gatra-production/package.json`
- Create: `GitHub/gatra-production/app/layout.tsx`
- Modify: `GitHub/gatra-production/tailwind.config.js` (add `app/` to content paths)

- [ ] **Step 1: Install CopilotKit packages**

Run: `cd GitHub/gatra-production && npm install @copilotkit/react-core@^1.54.1 @copilotkit/react-ui@^1.54.1 @copilotkit/runtime@^1.54.1`

- [ ] **Step 2: Create app/layout.tsx**

```tsx
// GitHub/gatra-production/app/layout.tsx
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "GATRA SOC",
  description: "GATRA Security Operations Center",
};

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-gray-950 text-white antialiased">
        {children}
      </body>
    </html>
  );
}
```

Note: CopilotKit provider is NOT in the root layout — it will be scoped to `/soc-analyst` only, to avoid affecting any other App Router pages.

- [ ] **Step 3: Add `app/` to Tailwind content paths**

In `GitHub/gatra-production/tailwind.config.js`, update the `content` array:

```javascript
content: [
  './pages/**/*.{js,ts,jsx,tsx}',
  './components/**/*.{js,ts,jsx,tsx}',
  './app/**/*.{js,ts,jsx,tsx}',  // Add this line
],
```

- [ ] **Step 4: Verify build succeeds with mixed routers**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds. Next.js auto-detects both `pages/` and `app/` directories.

- [ ] **Step 5: Commit**

```bash
cd GitHub/gatra-production
git add package.json package-lock.json app/layout.tsx tailwind.config.js
git commit -m "feat: set up App Router alongside Pages Router, install CopilotKit"
```

---

### Task 9: Create `/api/copilotkit` route with token minting and proxy

**Files:**
- Create: `GitHub/gatra-production/app/api/copilotkit/route.ts`

- [ ] **Step 1: Create the CopilotKit API route**

```typescript
// GitHub/gatra-production/app/api/copilotkit/route.ts

import {
  CopilotRuntime,
  ExperimentalEmptyAdapter,
  copilotRuntimeNextJSAppRouterEndpoint,
} from "@copilotkit/runtime";
import { LangGraphHttpAgent } from "@copilotkit/runtime/langgraph";
import { randomUUID } from "crypto";
import { SignJWT } from "jose";
import { NextRequest, NextResponse } from "next/server";

const AGENT_BACKEND_URL = process.env.AGENT_BACKEND_URL || "http://localhost:8123";
const AGENT_SERVICE_SECRET = process.env.AGENT_SERVICE_SECRET;

async function mintServiceToken(sub: string): Promise<string> {
  if (!AGENT_SERVICE_SECRET) {
    throw new Error("AGENT_SERVICE_SECRET not configured");
  }
  const secret = new TextEncoder().encode(AGENT_SERVICE_SECRET);
  return new SignJWT({
    sub,
    iss: "soc.gatra.ai",
    aud: "gatra-agent",
    source: "soc-site",
    role_ceiling: "analyst",
    route_scope: ["/agent/run"],
  })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(secret);
}

const runtime = new CopilotRuntime({
  agents: {
    gatra_soc: new LangGraphHttpAgent({
      url: AGENT_BACKEND_URL,
    }),
  },
});

const { handleRequest } = copilotRuntimeNextJSAppRouterEndpoint({
  runtime,
  serviceAdapter: new ExperimentalEmptyAdapter(),
  endpoint: "/api/copilotkit",
});

export async function POST(req: NextRequest) {
  const traceId = randomUUID();

  // TODO: Replace with actual SSO session validation (OD-1)
  // For now, extract user from a header or session cookie
  const userSub = "pilot-user@gatra.ai";

  try {
    const token = await mintServiceToken(userSub);

    // Inject auth headers for the downstream agent request
    req.headers.set("Authorization", `Bearer ${token}`);
    req.headers.set("X-Trace-ID", traceId);
    req.headers.set("X-Requested-Mode", "lite");

    return handleRequest(req);
  } catch (error) {
    console.error("CopilotKit proxy error:", { traceId, error });
    return NextResponse.json(
      { error: "Unable to connect to analyst service", trace_id: traceId },
      { status: 500 }
    );
  }
}
```

- [ ] **Step 2: Install jose dependency for JWT signing**

Run: `cd GitHub/gatra-production && npm install jose`

- [ ] **Step 3: Verify build succeeds**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd GitHub/gatra-production
git add app/api/copilotkit/route.ts package.json package-lock.json
git commit -m "feat: add /api/copilotkit route with JWT token minting and agent proxy"
```

---

### Task 10: Create `/soc-analyst` page with CopilotKit

**Files:**
- Create: `GitHub/gatra-production/app/soc-analyst/layout.tsx`
- Create: `GitHub/gatra-production/app/soc-analyst/page.tsx`
- Create: `GitHub/gatra-production/components/copilot/AnalystPanel.tsx`

- [ ] **Step 1: Create soc-analyst layout with scoped CopilotKit provider**

```tsx
// GitHub/gatra-production/app/soc-analyst/layout.tsx
"use client";

import { CopilotKit } from "@copilotkit/react-core";
import "@copilotkit/react-ui/styles.css";

export default function SocAnalystLayout({ children }: { children: React.ReactNode }) {
  return (
    <CopilotKit runtimeUrl="/api/copilotkit" agent="gatra_soc">
      {children}
    </CopilotKit>
  );
}
```

- [ ] **Step 2: Create the AnalystPanel component**

```tsx
// GitHub/gatra-production/components/copilot/AnalystPanel.tsx
"use client";

import { CopilotChat } from "@copilotkit/react-ui";
import { useCoAgent } from "@copilotkit/react-core";

interface GatraAgentState {
  session_id: string;
  incident_id: string;
  trace_id: string;
  pipeline_stage: string;
  current_agent: string;
  alerts: unknown[];
  proposed_actions: unknown[];
  executed_actions: unknown[];
  audit_log: unknown[];
  approval_pending: boolean;
}

const COPILOT_INSTRUCTIONS = `You are a GATRA SOC analyst assistant operating in read-only mode.
You can analyze threats, triage alerts, and recommend response actions.
You cannot execute actions — recommend them for review in the full Analyst Console.`;

export function AnalystPanel() {
  const { state, running } = useCoAgent<GatraAgentState>({
    name: "gatra_soc",
    initialState: {
      session_id: "",
      incident_id: "",
      trace_id: "",
      pipeline_stage: "idle",
      current_agent: "",
      alerts: [],
      proposed_actions: [],
      executed_actions: [],
      audit_log: [],
      approval_pending: false,
    },
  });

  return (
    <div className="flex h-full flex-col">
      <CopilotChat
        className="flex-1"
        instructions={COPILOT_INSTRUCTIONS}
        labels={{
          title: "GATRA Analyst",
          initial: "Ask me about threats, alerts, or security incidents.",
          placeholder: "Describe a threat or ask about an alert...",
        }}
      />
      {running && (
        <div className="border-t border-gray-800 px-4 py-2 text-xs text-gray-500">
          Agent: {state.current_agent || "processing"} | Stage: {state.pipeline_stage}
        </div>
      )}
    </div>
  );
}
```

- [ ] **Step 3: Create the page**

```tsx
// GitHub/gatra-production/app/soc-analyst/page.tsx

import { AnalystPanel } from "@/components/copilot/AnalystPanel";

const COPILOT_FULL_CONSOLE_URL = process.env.NEXT_PUBLIC_COPILOT_CONSOLE_URL || "https://console.soc.gatra.ai";

export default function SocAnalystPage() {
  return (
    <div className="flex h-screen flex-col bg-gray-950">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-gray-800 px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="text-lg font-bold text-white">GATRA</span>
          <span className="text-sm text-gray-400">Analyst Console</span>
          <span className="rounded bg-blue-900 px-2 py-0.5 text-xs text-blue-300">READ-ONLY</span>
        </div>
        <div className="flex items-center gap-4">
          <a
            href={COPILOT_FULL_CONSOLE_URL}
            className="text-sm text-gray-400 hover:text-white"
            target="_blank"
            rel="noopener noreferrer"
          >
            Launch Full Console &rarr;
          </a>
        </div>
      </header>

      {/* Chat Panel */}
      <main className="flex-1 overflow-hidden">
        <AnalystPanel />
      </main>
    </div>
  );
}
```

- [ ] **Step 4: Verify build succeeds**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds, `/soc-analyst` route is generated

- [ ] **Step 5: Commit**

```bash
cd GitHub/gatra-production
git add app/soc-analyst/ components/copilot/AnalystPanel.tsx
git commit -m "feat: add /soc-analyst page with CopilotKit chat panel"
```

---

## Workstream D: Generative UI Components

### Task 11: Create LiteModeGuard wrapper

**Files:**
- Create: `GitHub/gatra-production/components/copilot/LiteModeGuard.tsx`

- [ ] **Step 1: Create LiteModeGuard**

```tsx
// GitHub/gatra-production/components/copilot/LiteModeGuard.tsx
"use client";

import type { ReactNode } from "react";

interface LiteModeGuardProps {
  mode: "full" | "lite";
  executable?: boolean;
  children: ReactNode;
}

export function LiteModeGuard({ mode, executable, children }: LiteModeGuardProps) {
  if (mode === "lite" && executable) {
    return (
      <div className="rounded-lg border border-yellow-800 bg-yellow-950 px-4 py-3 text-sm text-yellow-300">
        View-only recommendation — execution available in the full Analyst Console
      </div>
    );
  }
  return <>{children}</>;
}
```

- [ ] **Step 2: Commit**

```bash
cd GitHub/gatra-production
git add components/copilot/LiteModeGuard.tsx
git commit -m "feat: add LiteModeGuard defensive wrapper component"
```

---

### Task 12: Copy and adapt AlertCard, MitreCard, VulnCard

**Files:**
- Create: `GitHub/gatra-production/components/copilot/AlertCard.tsx`
- Create: `GitHub/gatra-production/components/copilot/MitreCard.tsx`
- Create: `GitHub/gatra-production/components/copilot/VulnCard.tsx`

Source of truth: `worldmonitor/gatra-copilot/components/chat/`

- [ ] **Step 1: Copy AlertCard with provenance header and mode prop**

```tsx
// GitHub/gatra-production/components/copilot/AlertCard.tsx
// SOURCE: gatra-copilot/components/chat/AlertCard.tsx
// SYNCED FROM: commit HEAD
// LAST SYNCED: 2026-04-04

"use client";

import { LiteModeGuard } from "./LiteModeGuard";

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: "bg-red-600 text-white",
  HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black",
  LOW: "bg-blue-500 text-white",
};

interface AlertCardProps {
  severity: Severity;
  mitre_id: string;
  mitre_name: string;
  confidence: number;
  description: string;
  location_name?: string;
  infrastructure?: string;
  timestamp: string;
  status: "complete" | "inProgress";
  mode: "full" | "lite";
}

export function AlertCard(props: AlertCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-24 rounded bg-gray-700" />
        <div className="mt-2 h-3 w-48 rounded bg-gray-700" />
      </div>
    );
  }
  const colorClass = SEVERITY_COLORS[props.severity] ?? "bg-gray-500 text-white";
  return (
    <LiteModeGuard mode={props.mode} executable={false}>
      <div className="rounded-lg border border-gray-700 bg-gray-900 p-4">
        <div className="flex items-center gap-2">
          <span className={`rounded px-2 py-0.5 text-xs font-bold ${colorClass}`}>{props.severity}</span>
          <code className="text-sm text-gray-400">{props.mitre_id}</code>
          <span className="text-sm text-gray-300">{props.mitre_name}</span>
        </div>
        <p className="mt-2 text-sm text-gray-300">{props.description}</p>
        <div className="mt-2 flex gap-4 text-xs text-gray-500">
          <span>Confidence: {Math.round(props.confidence * 100)}%</span>
          {props.location_name && <span>{props.location_name}</span>}
          {props.infrastructure && <span>{props.infrastructure}</span>}
          <span>{new Date(props.timestamp).toLocaleTimeString()}</span>
        </div>
      </div>
    </LiteModeGuard>
  );
}
```

- [ ] **Step 2: Copy MitreCard with provenance header and mode prop**

```tsx
// GitHub/gatra-production/components/copilot/MitreCard.tsx
// SOURCE: gatra-copilot/components/chat/MitreCard.tsx
// SYNCED FROM: commit HEAD
// LAST SYNCED: 2026-04-04

"use client";

import { LiteModeGuard } from "./LiteModeGuard";

interface MitreCardProps {
  kill_chain_phase: string;
  actor_attribution: string;
  campaign?: string;
  iocs: string[];
  confidence: number;
  status: "complete" | "inProgress";
  mode: "full" | "lite";
}

export function MitreCard(props: MitreCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-32 rounded bg-gray-700" />
      </div>
    );
  }
  return (
    <LiteModeGuard mode={props.mode} executable={false}>
      <div className="rounded-lg border border-purple-700 bg-gray-900 p-4">
        <div className="text-sm font-bold text-purple-400">MITRE ATT&amp;CK Analysis</div>
        <div className="mt-2 space-y-1 text-sm text-gray-300">
          <p>Kill Chain: <strong>{props.kill_chain_phase}</strong></p>
          <p>Attribution: <strong>{props.actor_attribution}</strong></p>
          {props.campaign && <p>Campaign: {props.campaign}</p>}
          <p>Confidence: {Math.round(props.confidence * 100)}%</p>
        </div>
        {props.iocs.length > 0 && (
          <div className="mt-2">
            <span className="text-xs font-medium text-gray-500">IOCs:</span>
            <ul className="mt-1 space-y-0.5">
              {props.iocs.map((ioc, i) => (
                <li key={i} className="font-mono text-xs text-gray-400">{ioc}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </LiteModeGuard>
  );
}
```

- [ ] **Step 3: Copy VulnCard with provenance header and mode prop**

```tsx
// GitHub/gatra-production/components/copilot/VulnCard.tsx
// SOURCE: gatra-copilot/components/chat/VulnCard.tsx
// SYNCED FROM: commit HEAD
// LAST SYNCED: 2026-04-04

"use client";

import { LiteModeGuard } from "./LiteModeGuard";

interface VulnCardProps {
  cve_id: string;
  cvss_v4_score: number;
  epss_percentile: number;
  affected_products: string[];
  patch_available: boolean;
  cisa_kev: boolean;
  recommendation: string;
  status: "complete" | "inProgress";
  mode: "full" | "lite";
}

export function VulnCard(props: VulnCardProps) {
  if (props.status !== "complete") {
    return (
      <div className="animate-pulse rounded-lg border border-gray-700 bg-gray-800 p-4">
        <div className="h-4 w-28 rounded bg-gray-700" />
      </div>
    );
  }
  return (
    <LiteModeGuard mode={props.mode} executable={false}>
      <div className="rounded-lg border border-cyan-700 bg-gray-900 p-4">
        <div className="flex items-center gap-2">
          <code className="text-sm font-bold text-cyan-400">{props.cve_id}</code>
          {props.cisa_kev && (
            <span className="rounded bg-red-700 px-1.5 py-0.5 text-xs font-bold text-white">CISA KEV</span>
          )}
        </div>
        <div className="mt-2 grid grid-cols-2 gap-2 text-sm text-gray-300">
          <span>CVSS v4: <strong>{props.cvss_v4_score.toFixed(1)}</strong></span>
          <span>EPSS: <strong>{(props.epss_percentile * 100).toFixed(1)}%</strong></span>
          <span>Patch: {props.patch_available ? "Available" : "None"}</span>
        </div>
        <p className="mt-2 text-sm text-gray-400">{props.recommendation}</p>
      </div>
    </LiteModeGuard>
  );
}
```

- [ ] **Step 4: Verify build succeeds**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds

- [ ] **Step 5: Commit**

```bash
cd GitHub/gatra-production
git add components/copilot/AlertCard.tsx components/copilot/MitreCard.tsx components/copilot/VulnCard.tsx
git commit -m "feat: copy generative UI components from gatra-copilot with lite mode support"
```

---

### Task 13: Add "Launch Analyst Console" CTA to /soc page

**Files:**
- Modify: `GitHub/gatra-production/pages/soc.tsx`

- [ ] **Step 1: Add CTA button to the soc.tsx header area**

In `pages/soc.tsx`, locate the header `<div>` (around lines 22-50). Add a "Launch Analyst Console" link after the Play button (around line 48):

```tsx
{process.env.NEXT_PUBLIC_SOC_ANALYST_ENABLED === 'true' && (
  <a
    href="/soc-analyst"
    style={{
      padding: '0.5rem 1.5rem',
      background: 'linear-gradient(135deg, #2563eb, #06b6d4)',
      color: 'white',
      borderRadius: '0.5rem',
      fontWeight: '600',
      textDecoration: 'none',
      fontSize: '0.875rem',
    }}
  >
    Launch Analyst Console
  </a>
)}
```

- [ ] **Step 2: Verify build succeeds**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds. CTA is hidden when env var is not set.

- [ ] **Step 3: Commit**

```bash
cd GitHub/gatra-production
git add pages/soc.tsx
git commit -m "feat: add 'Launch Analyst Console' CTA to /soc page (behind feature flag)"
```

---

## Workstream E: Observability

### Task 14: Add trace_id generation and structured logging to /api/copilotkit

**Files:**
- Modify: `GitHub/gatra-production/app/api/copilotkit/route.ts`

The trace_id generation is already in the route from Task 9. This task adds structured logging.

- [ ] **Step 1: Add structured logging to the route**

Update the route's POST handler to log structured fields on every request:

```typescript
// Add at the top of the POST function, after traceId generation:
console.log(JSON.stringify({
  event: "copilotkit_request",
  trace_id: traceId,
  sub: userSub,
  source: "soc-site",
  requested_mode: "lite",
  timestamp: new Date().toISOString(),
}));

// Add in the catch block:
console.error(JSON.stringify({
  event: "copilotkit_error",
  trace_id: traceId,
  sub: userSub,
  error: error instanceof Error ? error.message : "unknown",
  route_outcome: "error",
  timestamp: new Date().toISOString(),
}));
```

- [ ] **Step 2: Commit**

```bash
cd GitHub/gatra-production
git add app/api/copilotkit/route.ts
git commit -m "feat: add structured logging with trace_id to /api/copilotkit"
```

---

### Task 15: Add rate limiting to /api/copilotkit

**Files:**
- Create: `GitHub/gatra-production/lib/rate-limit.ts`
- Modify: `GitHub/gatra-production/app/api/copilotkit/route.ts`

- [ ] **Step 1: Create simple in-memory rate limiter**

```typescript
// GitHub/gatra-production/lib/rate-limit.ts

const windows = new Map<string, { count: number; resetAt: number }>();

export function checkRateLimit(
  key: string,
  limit: number = 20,
  windowMs: number = 60_000,
): { allowed: boolean; retryAfter?: number } {
  const now = Date.now();
  const entry = windows.get(key);

  if (!entry || now > entry.resetAt) {
    windows.set(key, { count: 1, resetAt: now + windowMs });
    return { allowed: true };
  }

  if (entry.count >= limit) {
    const retryAfter = Math.ceil((entry.resetAt - now) / 1000);
    return { allowed: false, retryAfter };
  }

  entry.count++;
  return { allowed: true };
}
```

- [ ] **Step 2: Integrate rate limiter into the route**

In `app/api/copilotkit/route.ts`, add before the token minting:

```typescript
import { checkRateLimit } from "@/lib/rate-limit";

// Inside POST handler, after userSub:
const { allowed, retryAfter } = checkRateLimit(userSub);
if (!allowed) {
  console.log(JSON.stringify({
    event: "copilotkit_rate_limited",
    trace_id: traceId,
    sub: userSub,
    timestamp: new Date().toISOString(),
  }));
  return new NextResponse(
    JSON.stringify({ error: "Too many requests", trace_id: traceId }),
    { status: 429, headers: { "Retry-After": String(retryAfter) } }
  );
}
```

- [ ] **Step 3: Commit**

```bash
cd GitHub/gatra-production
git add lib/rate-limit.ts app/api/copilotkit/route.ts
git commit -m "feat: add per-user rate limiting (20 req/min) to /api/copilotkit"
```

---

## Workstream F: Rollout & Access Gating

### Task 16: Add pilot allowlist and feature flag gating to /soc-analyst

**Files:**
- Create: `GitHub/gatra-production/app/soc-analyst/middleware-utils.ts`
- Modify: `GitHub/gatra-production/app/soc-analyst/page.tsx`

- [ ] **Step 1: Create access control utility**

```typescript
// GitHub/gatra-production/app/soc-analyst/middleware-utils.ts

export function isAnalystConsoleEnabled(): boolean {
  return process.env.NEXT_PUBLIC_SOC_ANALYST_ENABLED === "true";
}

export function isPilotAllowlisted(email: string | null): boolean {
  if (!email) return false;
  const allowlist = process.env.SOC_ANALYST_PILOT_EMAILS || "";
  if (allowlist === "") return true; // No allowlist = open to all authenticated users (Phase 2+)
  const emails = allowlist.split(",").map((e) => e.trim().toLowerCase());
  return emails.includes(email.toLowerCase());
}
```

- [ ] **Step 2: Update page.tsx with access gating**

Update `app/soc-analyst/page.tsx` to check feature flag and show appropriate states:

```tsx
// GitHub/gatra-production/app/soc-analyst/page.tsx

import { AnalystPanel } from "@/components/copilot/AnalystPanel";

const COPILOT_FULL_CONSOLE_URL = process.env.NEXT_PUBLIC_COPILOT_CONSOLE_URL || "https://console.soc.gatra.ai";
const SOC_ANALYST_ENABLED = process.env.NEXT_PUBLIC_SOC_ANALYST_ENABLED === "true";

export default function SocAnalystPage() {
  if (!SOC_ANALYST_ENABLED) {
    return (
      <div className="flex h-screen items-center justify-center bg-gray-950">
        <div className="text-center">
          <h1 className="text-xl font-bold text-white">Analyst Console</h1>
          <p className="mt-2 text-gray-400">
            Analyst Console is not currently available.
          </p>
          <a href="/soc" className="mt-4 inline-block text-sm text-blue-400 hover:text-blue-300">
            &larr; Back to SOC Dashboard
          </a>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen flex-col bg-gray-950">
      <header className="flex items-center justify-between border-b border-gray-800 px-6 py-3">
        <div className="flex items-center gap-3">
          <span className="text-lg font-bold text-white">GATRA</span>
          <span className="text-sm text-gray-400">Analyst Console</span>
          <span className="rounded bg-blue-900 px-2 py-0.5 text-xs text-blue-300">READ-ONLY</span>
        </div>
        <div className="flex items-center gap-4">
          <a
            href={COPILOT_FULL_CONSOLE_URL}
            className="text-sm text-gray-400 hover:text-white"
            target="_blank"
            rel="noopener noreferrer"
          >
            Launch Full Console &rarr;
          </a>
        </div>
      </header>
      <main className="flex-1 overflow-hidden">
        <AnalystPanel />
      </main>
    </div>
  );
}
```

- [ ] **Step 3: Verify build**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds

- [ ] **Step 4: Commit**

```bash
cd GitHub/gatra-production
git add app/soc-analyst/middleware-utils.ts app/soc-analyst/page.tsx
git commit -m "feat: add feature flag gating and pilot allowlist for /soc-analyst"
```

---

### Task 17: Failure mode UI — degraded state when agent is unavailable

**Files:**
- Modify: `GitHub/gatra-production/components/copilot/AnalystPanel.tsx`

- [ ] **Step 1: Add error boundary and degraded state handling**

Update `AnalystPanel.tsx` to handle connection errors gracefully:

```tsx
// Add to AnalystPanel.tsx, after the existing imports:
import { useState } from "react";

// Inside AnalystPanel component, add error state:
const [connectionError, setConnectionError] = useState(false);

// Add error UI before the CopilotChat:
if (connectionError) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="text-center">
        <p className="text-lg text-gray-300">Analyst service is temporarily unavailable</p>
        <p className="mt-2 text-sm text-gray-500">
          The existing chatbot on the SOC dashboard is still available.
        </p>
        <button
          onClick={() => setConnectionError(false)}
          className="mt-4 rounded bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
        >
          Retry
        </button>
      </div>
    </div>
  );
}
```

- [ ] **Step 2: Commit**

```bash
cd GitHub/gatra-production
git add components/copilot/AnalystPanel.tsx
git commit -m "feat: add degraded state UI when analyst agent is unavailable"
```

---

### Task 18: Contract test fixtures

**Files:**
- Create: `GitHub/gatra-production/__tests__/fixtures/alert-card-payload.json`
- Create: `GitHub/gatra-production/__tests__/fixtures/mitre-card-payload.json`
- Create: `GitHub/gatra-production/__tests__/fixtures/vuln-card-payload.json`
- Create: `worldmonitor/gatra-agent/tests/fixtures/alert-card-payload.json` (same content)

- [ ] **Step 1: Create shared fixture files**

```json
// __tests__/fixtures/alert-card-payload.json
{
  "severity": "HIGH",
  "mitre_id": "T1566.001",
  "mitre_name": "Spearphishing Attachment",
  "confidence": 0.92,
  "description": "Suspicious email with macro-enabled attachment detected",
  "location_name": "Jakarta NOC",
  "infrastructure": "mail-gw-01",
  "timestamp": "2026-04-04T10:00:00Z",
  "status": "complete",
  "mode": "lite"
}
```

```json
// __tests__/fixtures/mitre-card-payload.json
{
  "kill_chain_phase": "delivery",
  "actor_attribution": "UNC2452",
  "campaign": "SolarStorm-2",
  "iocs": ["10.0.0.1", "evil.example.com", "abc123def456"],
  "confidence": 0.85,
  "status": "complete",
  "mode": "lite"
}
```

```json
// __tests__/fixtures/vuln-card-payload.json
{
  "cve_id": "CVE-2026-1234",
  "cvss_v4_score": 9.1,
  "epss_percentile": 0.95,
  "affected_products": ["Apache Log4j 2.x"],
  "patch_available": true,
  "cisa_kev": true,
  "recommendation": "Apply patch immediately. Exploitation observed in the wild.",
  "status": "complete",
  "mode": "lite"
}
```

- [ ] **Step 2: Copy fixtures to gatra-agent tests**

```bash
mkdir -p worldmonitor/gatra-agent/tests/fixtures
cp GitHub/gatra-production/__tests__/fixtures/*.json worldmonitor/gatra-agent/tests/fixtures/
```

- [ ] **Step 3: Commit both**

```bash
cd GitHub/gatra-production
git add __tests__/fixtures/
git commit -m "test: add contract test fixtures for generative UI payloads"

cd worldmonitor/gatra-agent
git add tests/fixtures/
git commit -m "test: add shared contract test fixtures for generative UI payloads"
```

---

## Final Verification

### Task 19: Full build and smoke test

- [ ] **Step 1: Run full backend test suite**

Run: `cd worldmonitor/gatra-agent && python -m pytest -v`
Expected: All tests PASS

- [ ] **Step 2: Run frontend build**

Run: `cd GitHub/gatra-production && npm run build`
Expected: Build succeeds with both `pages/` and `app/` routes

- [ ] **Step 3: Verify existing pages are unaffected**

Run: `cd GitHub/gatra-production && npm run dev`
Then manually verify:
- `http://localhost:3000/` — home page loads normally
- `http://localhost:3000/soc` — SOC page loads, chatbot widget works
- `http://localhost:3000/soc-analyst` — shows "not available" (flag is off)

- [ ] **Step 4: Test with feature flag on**

Set `NEXT_PUBLIC_SOC_ANALYST_ENABLED=true` in `.env.local`, restart dev server.
- `http://localhost:3000/soc` — "Launch Analyst Console" CTA visible
- `http://localhost:3000/soc-analyst` — CopilotKit chat panel loads (will show connection error if agent isn't running, which is expected)

- [ ] **Step 5: Final commit**

```bash
cd GitHub/gatra-production
git add -A
git commit -m "chore: final integration verification — all builds passing"
```
