import base64
import dataclasses
import enum
import hashlib
import hmac
import json
import os
import time
from typing import Optional

from fastapi import Cookie, Depends, HTTPException, Security, status
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "sp-admin-secret-key-2026")
VIEWER_API_KEY = os.getenv("VIEWER_API_KEY", "sp-viewer-readonly-key-2026")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "subnetpulse-admin")

VIEWER_USERNAME = os.getenv("VIEWER_USERNAME", "auditor")
VIEWER_PASSWORD = os.getenv("VIEWER_PASSWORD", "subnetpulse-viewer")

AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "subnetpulse-hmac-signing-secret-2026")
AUTH_TOKEN_TTL_SECONDS = int(os.getenv("AUTH_TOKEN_TTL_SECONDS", str(12 * 3600)))
SESSION_COOKIE_NAME = "subnetpulse_session"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"


@dataclasses.dataclass(frozen=True)
class AuthPrincipal:
    username: str
    role: UserRole
    auth_method: str


_bearer_scheme = HTTPBearer(auto_error=False)
_basic_scheme = HTTPBasic(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(
    username: str,
    role: UserRole,
    ttl_seconds: int = AUTH_TOKEN_TTL_SECONDS,
) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role.value,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{payload_b64}.{sig_b64}"


def verify_access_token(token: str) -> Optional[AuthPrincipal]:
    if not token or "." not in token:
        return None
    parts = token.split(".")
    if len(parts) != 2:
        return None
    payload_b64, sig_b64 = parts
    expected_sig = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    expected_sig_b64 = _b64url_encode(expected_sig)
    if not hmac.compare_digest(sig_b64, expected_sig_b64):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
    except Exception:
        return None

    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < int(time.time()):
        return None

    username = payload.get("sub")
    role_raw = payload.get("role")
    if not username or role_raw not in (UserRole.ADMIN.value, UserRole.VIEWER.value):
        return None

    return AuthPrincipal(
        username=str(username),
        role=UserRole(role_raw),
        auth_method="bearer_token",
    )


def _match_api_key(candidate: str) -> Optional[AuthPrincipal]:
    cleaned = candidate.strip()
    if not cleaned:
        return None
    if ADMIN_API_KEY and hmac.compare_digest(cleaned, ADMIN_API_KEY):
        return AuthPrincipal(username=ADMIN_USERNAME, role=UserRole.ADMIN, auth_method="api_key")
    if VIEWER_API_KEY and hmac.compare_digest(cleaned, VIEWER_API_KEY):
        return AuthPrincipal(username=VIEWER_USERNAME, role=UserRole.VIEWER, auth_method="api_key")
    return verify_access_token(cleaned)


def authenticate_credentials(
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[AuthPrincipal]:
    if api_key and api_key.strip():
        return _match_api_key(api_key)

    if username is not None and password is not None:
        u = username.strip()
        if hmac.compare_digest(u, ADMIN_USERNAME) and hmac.compare_digest(password, ADMIN_PASSWORD):
            return AuthPrincipal(username=ADMIN_USERNAME, role=UserRole.ADMIN, auth_method="password")
        if hmac.compare_digest(u, VIEWER_USERNAME) and hmac.compare_digest(password, VIEWER_PASSWORD):
            return AuthPrincipal(username=VIEWER_USERNAME, role=UserRole.VIEWER, auth_method="password")

    return None


def get_optional_principal(
    api_key: Optional[str] = Security(_api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme),
    basic: Optional[HTTPBasicCredentials] = Security(_basic_scheme),
    session_cookie: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
) -> Optional[AuthPrincipal]:
    if api_key:
        principal = _match_api_key(api_key)
        if principal:
            return principal

    if bearer and bearer.scheme.lower() == "bearer" and bearer.credentials:
        principal = _match_api_key(bearer.credentials)
        if principal:
            return principal

    if basic and basic.username is not None and basic.password is not None:
        principal = authenticate_credentials(username=basic.username, password=basic.password)
        if principal:
            return principal

    if session_cookie:
        principal = verify_access_token(session_cookie)
        if principal:
            return principal

    return None


def require_authenticated(
    principal: Optional[AuthPrincipal] = Depends(get_optional_principal),
) -> AuthPrincipal:
    if principal is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Provide a valid Bearer token, X-API-Key header, or Basic credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return principal


def require_admin(
    principal: AuthPrincipal = Depends(require_authenticated),
) -> AuthPrincipal:
    if principal.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required to perform this operation.",
        )
    return principal
