import time
import pytest
from agent.auth import mint_service_token, validate_service_token, TokenError

SECRET = "test-secret-key-at-least-32-chars-long"

def test_mint_token_creates_valid_jwt():
    token = mint_service_token(
        sub="user@gatra.ai", iss="soc.gatra.ai", aud="gatra-agent",
        source="soc-site", role_ceiling="analyst", route_scope=["/agent/run"],
        secret=SECRET, ttl_seconds=300,
    )
    assert isinstance(token, str)
    assert len(token.split(".")) == 3

def test_validate_token_returns_claims():
    token = mint_service_token(
        sub="user@gatra.ai", iss="soc.gatra.ai", aud="gatra-agent",
        source="soc-site", role_ceiling="analyst", route_scope=["/agent/run"],
        secret=SECRET, ttl_seconds=300,
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
