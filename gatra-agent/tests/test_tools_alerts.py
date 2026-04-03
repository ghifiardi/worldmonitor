import pytest
from agent.tools.alerts import fetch_alerts
from agent.tools.threat_intel import lookup_ioc

@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")

async def test_fetch_alerts(httpx_mock):
    httpx_mock.add_response(url="https://test.example.com/api/gatra-data?severity=all&limit=20",
        json={"alerts": [{"id": "a1", "severity": "HIGH"}]})
    result = await fetch_alerts.ainvoke({"severity": "all", "limit": 20})
    assert "alerts" in result

async def test_lookup_ioc(httpx_mock):
    httpx_mock.add_response(url="https://test.example.com/api/ioc-lookup?ioc=45.33.32.156&type=ip",
        json={"found": True, "source": "VirusTotal", "malicious": True})
    result = await lookup_ioc.ainvoke({"ioc": "45.33.32.156", "ioc_type": "ip"})
    assert result["found"] is True
