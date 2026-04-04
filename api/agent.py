"""
Vercel Python serverless function — GATRA LangGraph agent endpoint.

Wraps the FastAPI ASGI app from gatra-agent/server.py for Vercel deployment.
This function serves the AG-UI/CopilotKit protocol at /api/agent.

POST /api/agent  — AG-UI SSE endpoint (used by CopilotKit LangGraphHttpAgent)
GET  /api/agent  — health check
"""
import os
import sys

# Add gatra-agent directory to Python path so imports work
agent_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "gatra-agent")
if agent_dir not in sys.path:
    sys.path.insert(0, agent_dir)

# Set defaults for required env vars if not set
os.environ.setdefault("AGENT_SERVICE_SECRET", os.environ.get("AGENT_SERVICE_SECRET", ""))
os.environ.setdefault("WORLDMONITOR_API_URL", "https://worldmonitor-gatra.vercel.app")

from http.server import BaseHTTPRequestHandler
import json
import asyncio

# Lazy-load the graph and auth to avoid import errors during cold start
_graph = None
_initialized = False


def _init():
    global _graph, _initialized
    if _initialized:
        return
    try:
        from agent.graph import build_graph
        _graph = build_graph()
        _initialized = True
    except Exception as e:
        print(f"Agent init error: {e}")
        _initialized = True  # Don't retry on every request


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Health check."""
        _init()
        status = "ok" if _graph is not None else "error"
        self.send_response(200 if _graph else 500)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps({"status": status, "agent": "gatra_soc"}).encode())

    def do_POST(self):
        """Forward to the FastAPI/AG-UI handler."""
        _init()

        if not _graph:
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Agent not initialized"}).encode())
            return

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b""

        try:
            # Import auth and validate token
            from agent.auth import validate_service_token, resolve_effective_mode, TokenError
            from agent.request_context import effective_mode_var, rbac_ceiling_var, trace_id_var

            secret = os.environ.get("AGENT_SERVICE_SECRET", "")
            if not secret:
                self.send_response(500)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "AGENT_SERVICE_SECRET not configured"}).encode())
                return

            auth_header = self.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing authorization"}).encode())
                return

            token = auth_header[7:]
            try:
                claims = validate_service_token(token, secret=secret, expected_aud="gatra-agent")
            except TokenError as e:
                status_code = 403 if "audience" in str(e) or "issuer" in str(e) else 401
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
                return

            # Set context vars for graph nodes
            effective_mode = resolve_effective_mode(
                source=claims.get("source", ""),
                requested_mode=self.headers.get("X-Requested-Mode"),
            )
            effective_mode_var.set(effective_mode)
            rbac_ceiling_var.set(claims.get("role_ceiling", "analyst"))
            trace_id_var.set(self.headers.get("X-Trace-ID", ""))

            # Parse the AG-UI request and invoke graph
            request_data = json.loads(body) if body else {}

            # Extract messages from CopilotKit/AG-UI protocol
            messages = request_data.get("messages", [])
            query = ""
            if messages:
                last_msg = messages[-1] if isinstance(messages, list) else messages
                if isinstance(last_msg, dict):
                    query = last_msg.get("content", "")

            # Invoke the graph
            import uuid
            graph_input = {
                "messages": messages,
                "mode": effective_mode,
                "session_id": request_data.get("threadId", str(uuid.uuid4())),
                "incident_id": str(uuid.uuid4()),
                "trace_id": self.headers.get("X-Trace-ID", str(uuid.uuid4())),
                "user_id": claims.get("sub", "unknown"),
                "user_role": claims.get("role_ceiling", "analyst"),
                "query": query,
            }

            config = {"configurable": {"thread_id": request_data.get("threadId", str(uuid.uuid4()))}}
            result = asyncio.get_event_loop().run_until_complete(_graph.ainvoke(graph_input, config))

            # Format response
            response_text = ""
            if result.get("messages"):
                for msg in reversed(result["messages"]):
                    if hasattr(msg, "content") and msg.content:
                        response_text = msg.content
                        break

            if not response_text and result.get("proposed_actions"):
                actions = result["proposed_actions"]
                response_text = f"Analysis complete. Found {len(actions)} recommended action(s):\n\n"
                for a in actions:
                    exec_status = "READ-ONLY" if not a.executable else "EXECUTABLE"
                    response_text += f"- **{a.action_type.upper()}** {a.target_value} [{exec_status}]: {a.rationale}\n"

            if not response_text:
                response_text = "Analysis complete. No immediate threats detected."

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({
                "messages": [{"role": "assistant", "content": response_text}],
                "threadId": graph_input["session_id"],
            }).encode())

        except Exception as e:
            print(f"Agent error: {e}")
            import traceback
            traceback.print_exc()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": str(e)}).encode())

    def do_OPTIONS(self):
        """CORS preflight."""
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Trace-ID, X-Requested-Mode")
        self.send_header("Access-Control-Max-Age", "86400")
        self.end_headers()
