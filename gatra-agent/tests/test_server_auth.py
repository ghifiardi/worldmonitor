import os
import pytest

os.environ["AGENT_SERVICE_SECRET"] = "test-secret-key-at-least-32-chars-long"

from fastapi.testclient import TestClient
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
