import pytest
from agent.tools.response import execute_action, scan_yara
from agent.tools.vulnerability import lookup_cves

@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("WORLDMONITOR_API_URL", "https://test.example.com")
    monkeypatch.setenv("GATRA_API_KEY", "test-key")
    monkeypatch.setenv("ACTION_DRY_RUN", "false")

async def test_execute_action(httpx_mock):
    httpx_mock.add_response(url="https://test.example.com/api/response-actions",
        json={"success": True, "action_id": "act1"})
    result = await execute_action.ainvoke({"action_type": "block", "target_type": "ip",
        "target_value": "45.33.32.156", "idempotency_key": "idem-001"})
    assert result["success"] is True

async def test_scan_yara(httpx_mock):
    httpx_mock.add_response(url="https://test.example.com/api/response-actions",
        json={"matches": ["MALWARE_Trojan_Generic"]})
    result = await scan_yara.ainvoke({"file_hash": "abc123", "scan_type": "hash"})
    assert "matches" in result

async def test_lookup_cves(httpx_mock):
    httpx_mock.add_response(url="https://test.example.com/api/cisa-kev?product=apache&limit=10",
        json={"cves": [{"id": "CVE-2024-1234", "cvss": 9.8}]})
    result = await lookup_cves.ainvoke({"product": "apache", "limit": 10})
    assert len(result["cves"]) == 1
