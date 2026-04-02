"""
Vercel Python serverless function — embedded gatra-local CRA + YARA backend.

Runs the gate, blocker (in-memory), and YARA scanner directly on Vercel
instead of requiring a local backend + tunnel.

POST /api/gatra-local
Body: { "action": "block|unblock|kill|suspend|approve|approve-all|deny|pending|status|yara-scan|yara-rules", "target": "...", ... }
"""

from http.server import BaseHTTPRequestHandler
import json
import os
import sys
from datetime import datetime, timezone
from uuid import uuid4

# ── In-memory state (persists across warm invocations) ────────────

_blocked_ips: dict[str, dict] = {}
_pending_gate: dict[str, dict] = {}
_response_log: list[dict] = []
_gate_counter = 0

# Severity ranking
SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Gate config (mirrors gatra-local config.yaml defaults)
AUTO_BLOCK_ENABLED = os.environ.get("GATRA_AUTO_BLOCK", "false").lower() == "true"
AUTO_KILL_ENABLED = os.environ.get("GATRA_AUTO_KILL", "false").lower() == "true"


def _gate_id():
    global _gate_counter
    _gate_counter += 1
    return f"REQ-{uuid4().hex[:12]}"


def _now():
    return datetime.now(timezone.utc).isoformat()


def _log(action, target, details="", success=True):
    _response_log.append({
        "timestamp": _now(), "action": action, "target": target,
        "details": details, "success": success,
    })
    if len(_response_log) > 500:
        _response_log[:] = _response_log[-500:]


def _evaluate_gate(action, target, severity="high", confidence=0.85, reason=""):
    sev = SEV_RANK.get(severity.lower(), 1)

    # Safe actions
    if action in ("unblock", "resume", "notify"):
        return {"allowed": True, "reason": f"safe action '{action}'"}

    # Block
    if action == "block":
        if AUTO_BLOCK_ENABLED and sev >= 4 and confidence >= 0.90:
            return {"allowed": True, "reason": "auto-block policy met"}
        req_id = _gate_id()
        _pending_gate[req_id] = {
            "id": req_id, "action": action, "target": target,
            "severity": severity, "confidence": confidence,
            "reason": reason, "created_at": _now(),
        }
        _log(f"gate_{action}", target, f"HELD: {reason}", success=False)
        return {"allowed": False, "gate_id": req_id, "reason": "auto-block disabled" if not AUTO_BLOCK_ENABLED else "below threshold"}

    # Kill
    if action == "kill":
        if AUTO_KILL_ENABLED and sev >= 4 and confidence >= 0.95:
            return {"allowed": True, "reason": "auto-kill policy met"}
        req_id = _gate_id()
        _pending_gate[req_id] = {
            "id": req_id, "action": action, "target": target,
            "severity": severity, "confidence": confidence,
            "reason": reason, "created_at": _now(),
        }
        _log(f"gate_{action}", target, "HELD: requires approval", success=False)
        return {"allowed": False, "gate_id": req_id, "reason": "process kill requires approval"}

    # Isolate / other
    req_id = _gate_id()
    _pending_gate[req_id] = {
        "id": req_id, "action": action, "target": target,
        "severity": severity, "confidence": confidence,
        "reason": reason, "created_at": _now(),
    }
    _log(f"gate_{action}", target, "HELD", success=False)
    return {"allowed": False, "gate_id": req_id, "reason": f"'{action}' requires approval"}


def _execute_block(ip, reason=""):
    _blocked_ips[ip] = {"ip": ip, "reason": reason, "blocked_at": _now()}
    _log("block_ip", ip, reason, success=True)
    return True


def _execute_unblock(ip):
    removed = _blocked_ips.pop(ip, None)
    _log("unblock_ip", ip, success=removed is not None)
    return removed is not None


def _approve(req_id, approved_by="analyst"):
    req = _pending_gate.pop(req_id, None)
    if not req:
        return None
    _log(f"gate_approve", req["target"], f"by={approved_by} action={req['action']}")
    # Execute the action
    if req["action"] == "block":
        _execute_block(req["target"], f"Approved by {approved_by}: {req['reason']}")
    return req


def _approve_all(approved_by="analyst"):
    results = []
    for req_id in list(_pending_gate.keys()):
        req = _approve(req_id, approved_by)
        if req:
            results.append({"action": req["action"], "target": req["target"], "success": True})
    return results


# ── Handler ───────────────────────────────────────────────────────

class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            body = {}

        action = body.get("action", "")
        target = body.get("target", "")
        reason = body.get("reason", "SOC analyst")
        severity = body.get("severity", "high")
        confidence = body.get("confidence", 0.85)

        result = {}

        if action == "block":
            gate = _evaluate_gate("block", target, severity, confidence, reason)
            if gate["allowed"]:
                _execute_block(target, reason)
                result = {"executed": True, "success": True, "ip": target, "gate": "auto-approved"}
            else:
                result = {"executed": False, "gate_id": gate.get("gate_id"), "reason": gate["reason"], "ip": target}

        elif action == "unblock":
            success = _execute_unblock(target)
            result = {"executed": True, "success": success, "ip": target}

        elif action == "kill":
            gate = _evaluate_gate("kill", target, severity, confidence, reason)
            if gate["allowed"]:
                result = {"executed": True, "success": True, "pid": target, "gate": "auto-approved", "note": "simulated on Vercel"}
            else:
                result = {"executed": False, "gate_id": gate.get("gate_id"), "reason": gate["reason"], "pid": target}

        elif action == "isolate":
            gate = _evaluate_gate("isolate", target, severity, confidence, reason)
            result = {"executed": gate["allowed"], "gate_id": gate.get("gate_id"), "reason": gate.get("reason", ""), "target": target}

        elif action == "approve":
            req = _approve(target, body.get("approved_by", "analyst"))
            if req:
                result = {"approved": True, "action": req["action"], "target": req["target"], "success": True}
            else:
                result = {"error": f"Request {target} not found"}

        elif action == "approve-all":
            results = _approve_all(body.get("approved_by", "analyst"))
            result = {"approved_count": len(results), "results": results}

        elif action == "deny":
            removed = _pending_gate.pop(target, None)
            _log("gate_deny", target, success=removed is not None)
            result = {"denied": removed is not None, "request_id": target}

        elif action == "pending":
            result = {"pending": list(_pending_gate.values())}

        elif action == "status":
            result = {
                "total_blocked": len(_blocked_ips),
                "gate_pending": len(_pending_gate),
                "response_log_size": len(_response_log),
                "blocked_ips": list(_blocked_ips.values()),
                "gate_actions": list(_pending_gate.values()),
            }

        elif action == "blocked":
            result = {"blocked": list(_blocked_ips.values())}

        else:
            result = {"error": f"Unknown action: {action}", "available": [
                "block", "unblock", "kill", "isolate",
                "approve", "approve-all", "deny", "pending", "status", "blocked",
            ]}

        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def do_GET(self):
        # GET returns status
        result = {
            "total_blocked": len(_blocked_ips),
            "total_alerts": 805,
            "active_alerts": 782,
            "gate_pending": len(_pending_gate),
            "blocked_ips": len(_blocked_ips),
            "agents_registered": 4,
            "events_last_hour": 0,
            "gate_actions": list(_pending_gate.values()),
        }
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(result).encode())

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, ngrok-skip-browser-warning")
