"""Bearer-token auth for the write endpoints. Read endpoints (/api/alerts, dashboard,
metrics) stay open on purpose: this is a read-only analyst enclave, and gating the
dashboard would make the demo unusable.

The token is compared with secrets.compare_digest (constant-time) and is supplied by the
SENTINEL_API_TOKEN env var. When the variable is unset the write endpoints REFUSE traffic
rather than falling open — a missing token must never mean "unauthenticated writes allowed".
"""
from __future__ import annotations
import hmac
import os
import secrets
from fastapi import Header, HTTPException

ENV_VAR = 'SENTINEL_API_TOKEN'
BEARER = 'bearer'


def configured_token() -> str | None:
    t = os.getenv(ENV_VAR, '').strip()
    return t or None


def write_auth_enabled() -> bool:
    return configured_token() is not None


def require_write_token(authorization: str | None = Header(default=None)) -> str:
    """FastAPI dependency. 503 if no token is configured, 401 if the presented one is wrong."""
    expected = configured_token()
    if expected is None:
        raise HTTPException(status_code=503, detail=(
            f'write endpoints are disabled: set {ENV_VAR} to a secret value '
            '(generate one with: python3 -c "import secrets;print(secrets.token_urlsafe(32))")'))
    if not authorization or not authorization.lower().startswith(BEARER + ' '):
        raise HTTPException(status_code=401, detail=f'Authorization: Bearer <{ENV_VAR}> required')
    presented = authorization[len(BEARER) + 1:].strip()
    if not presented or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=401, detail='invalid token')
    return presented


def mint(secret: str) -> str:
    """Helper for scripts/tests: the header value a client must send."""
    return f'{BEARER} {secret}' if secret else ''


__all__ = ['ENV_VAR', 'BEARER', 'configured_token', 'write_auth_enabled',
           'require_write_token', 'mint', 'secrets']
