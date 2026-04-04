import time
import jwt


class TokenError(Exception):
    """Raised when a service token is invalid."""
    pass


REQUIRED_CLAIMS = {"sub", "iss", "aud", "exp", "source", "role_ceiling", "route_scope"}


def mint_service_token(*, sub, iss, aud, source, role_ceiling, route_scope, secret, ttl_seconds):
    now = time.time()
    payload = {
        "sub": sub, "iss": iss, "aud": aud, "source": source,
        "role_ceiling": role_ceiling, "route_scope": route_scope,
        "iat": now, "exp": now + ttl_seconds,
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def validate_service_token(token, *, secret, expected_aud):
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


def resolve_effective_mode(*, source, requested_mode):
    if source == "soc-site":
        return "lite"
    return requested_mode or "full"
