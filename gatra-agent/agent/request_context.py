"""Request-scoped context variables for bridging middleware → graph nodes.

The AG-UI/CopilotKit endpoint invokes the LangGraph graph without passing
request.state through to graph nodes.  We use Python contextvars (which
propagate through the same async context) so the ServiceTokenMiddleware
can set the effective_mode and the router node can read it to override
GatraState.mode — enforcing the security boundary server-side.
"""
from __future__ import annotations

import contextvars

effective_mode_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "effective_mode", default="full"
)

rbac_ceiling_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "rbac_ceiling", default="admin"
)

trace_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "trace_id", default=""
)
