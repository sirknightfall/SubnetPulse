import base64
import dataclasses
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Optional, Tuple

from fastapi import Cookie, Depends, HTTPException, Security, status
from fastapi.security import (
    APIKeyHeader,
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)
from sqlalchemy.orm import Session, joinedload

from database import SessionLocal, get_db
from models import User, UserAPIKey, UserRole, utcnow

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "sp-admin-secret-key-2026")
VIEWER_API_KEY = os.getenv("VIEWER_API_KEY", "sp-viewer-readonly-key-2026")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "subnetpulse-admin")

VIEWER_USERNAME = os.getenv("VIEWER_USERNAME", "auditor")
VIEWER_PASSWORD = os.getenv("VIEWER_PASSWORD", "subnetpulse-viewer")

AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "subnetpulse-hmac-signing-secret-2026")
AUTH_TOKEN_TTL_SECONDS = int(os.getenv("AUTH_TOKEN_TTL_SECONDS", str(12 * 3600)))
SESSION_COOKIE_NAME = "subnetpulse_session"
PBKDF2_ITERATIONS = 260_000


@dataclasses.dataclass(frozen=True)
class AuthPrincipal:
    username: str
    role: UserRole
    auth_method: str
    user_id: Optional[int] = None


_bearer_scheme = HTTPBearer(auto_error=False)
_basic_scheme = HTTPBasic(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    salt_hex = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        iterations,
    )
    return f"pbkdf2_sha256${iterations}${salt_hex}${dk.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    if not plain_password or not password_hash:
        return False
    parts = password_hash.split("$")
    if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
        return False
    try:
        iterations = int(parts[1])
        salt_bytes = bytes.fromhex(parts[2])
        expected_hex = parts[3]
    except ValueError:
        return False

    candidate_dk = hashlib.pbkdf2_hmac(
        "sha256",
        plain_password.encode("utf-8"),
        salt_bytes,
        iterations,
    )
    return hmac.compare_digest(candidate_dk.hex(), expected_hex)


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.strip().encode("utf-8")).hexdigest()


def generate_scoped_api_key() -> Tuple[str, str, str]:
    """
    Generates a random scoped API key and returns (raw_key, key_prefix, key_hash).
    """
    raw_key = f"sp_live_{secrets.token_urlsafe(24)}"
    key_prefix = raw_key[:12]
    key_hash = hash_api_key(raw_key)
    return raw_key, key_prefix, key_hash


def seed_initial_users(db: Session) -> None:
    """
    Seeds the initial administrator and viewer accounts from environment variables
    on first boot if no users exist in SQLite yet.
    """
    existing_count = db.query(User).count()
    if existing_count > 0:
        return

    admin_user = User(
        username=ADMIN_USERNAME,
        password_hash=hash_password(ADMIN_PASSWORD),
        role=UserRole.ADMIN,
        is_active=True,
    )
    db.add(admin_user)
    db.flush()

    if ADMIN_API_KEY:
        db.add(
            UserAPIKey(
                user_id=admin_user.id,
                name="Default Admin API Key",
                key_prefix=ADMIN_API_KEY[:12],
                key_hash=hash_api_key(ADMIN_API_KEY),
                is_active=True,
            )
        )

    if VIEWER_USERNAME and VIEWER_USERNAME.lower() != ADMIN_USERNAME.lower():
        viewer_user = User(
            username=VIEWER_USERNAME,
            password_hash=hash_password(VIEWER_PASSWORD),
            role=UserRole.VIEWER,
            is_active=True,
        )
        db.add(viewer_user)
        db.flush()

        if VIEWER_API_KEY and VIEWER_API_KEY != ADMIN_API_KEY:
            db.add(
                UserAPIKey(
                    user_id=viewer_user.id,
                    name="Default Viewer API Key",
                    key_prefix=VIEWER_API_KEY[:12],
                    key_hash=hash_api_key(VIEWER_API_KEY),
                    is_active=True,
                )
            )

    db.commit()


def create_access_token(
    username: str,
    role: UserRole,
    ttl_seconds: int = AUTH_TOKEN_TTL_SECONDS,
    user_id: Optional[int] = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub": username,
        "role": role.value,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if user_id is not None:
        payload["uid"] = user_id
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    sig = hmac.new(
        AUTH_SECRET_KEY.encode("utf-8"),
        payload_b64.encode("ascii"),
        hashlib.sha256,
    ).digest()
    sig_b64 = _b64url_encode(sig)
    return f"{payload_b64}.{sig_b64}"


def _resolve_db_user_principal(
    db: Session,
    username: str,
    auth_method: str,
) -> Optional[Tuple[bool, Optional[AuthPrincipal]]]:
    """
    Looks up `username` in SQLite when the `users` table has been seeded.
    Returns:
      - (False, None) if the `users` table is completely empty (fallback to env config)
      - (True, None) if the user was deleted or is inactive (`is_active == False`)
      - (True, AuthPrincipal) if the user is active in SQLite
    """
    try:
        has_any_user = db.query(User.id).first() is not None
    except Exception:
        return False, None

    if not has_any_user:
        return False, None

    user = db.query(User).filter(User.username.ilike(username.strip())).first()
    if user is None or not user.is_active:
        return True, None

    return True, AuthPrincipal(
        username=user.username,
        role=user.role,
        auth_method=auth_method,
        user_id=user.id,
    )


def verify_access_token(token: str, db: Optional[Session] = None) -> Optional[AuthPrincipal]:
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

    if db is not None:
        table_seeded, principal = _resolve_db_user_principal(db, str(username), "bearer_token")
        if table_seeded:
            return principal
    else:
        try:
            with SessionLocal() as local_db:
                table_seeded, principal = _resolve_db_user_principal(
                    local_db, str(username), "bearer_token"
                )
                if table_seeded:
                    return principal
        except Exception:
            pass

    return AuthPrincipal(
        username=str(username),
        role=UserRole(role_raw),
        auth_method="bearer_token",
        user_id=payload.get("uid"),
    )


def _match_api_key_in_db(db: Session, cleaned: str) -> Optional[Tuple[bool, Optional[AuthPrincipal]]]:
    """
    Checks whether `cleaned` matches a `UserAPIKey` in SQLite.
    Returns (True, principal_or_none) if matched (or matched an expired/inactive key),
    or (False, None) if no key hash matched.
    """
    candidate_hash = hash_api_key(cleaned)
    try:
        key_row = (
            db.query(UserAPIKey)
            .options(joinedload(UserAPIKey.user))
            .filter(UserAPIKey.key_hash == candidate_hash)
            .first()
        )
    except Exception:
        return False, None

    if key_row is None:
        return False, None

    if not key_row.is_active or key_row.user is None or not key_row.user.is_active:
        return True, None

    now = utcnow()
    if key_row.expires_at is not None:
        exp_dt = key_row.expires_at
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if exp_dt <= now:
            return True, None

    key_row.last_used_at = now
    db.commit()
    return True, AuthPrincipal(
        username=key_row.user.username,
        role=key_row.user.role,
        auth_method="api_key",
        user_id=key_row.user.id,
    )


def _match_api_key(candidate: str, db: Optional[Session] = None) -> Optional[AuthPrincipal]:
    cleaned = candidate.strip()
    if not cleaned:
        return None

    # 1. Check scoped per-user API keys in SQLite
    if db is not None:
        matched, principal = _match_api_key_in_db(db, cleaned)
        if matched:
            return principal
    else:
        try:
            with SessionLocal() as local_db:
                matched, principal = _match_api_key_in_db(local_db, cleaned)
                if matched:
                    return principal
        except Exception:
            pass

    # 2. Check environment fallback keys (respecting DB user active status if seeded)
    if ADMIN_API_KEY and hmac.compare_digest(cleaned, ADMIN_API_KEY):
        if db is not None:
            seeded, principal = _resolve_db_user_principal(db, ADMIN_USERNAME, "api_key")
            if seeded:
                return principal
        return AuthPrincipal(username=ADMIN_USERNAME, role=UserRole.ADMIN, auth_method="api_key")

    if VIEWER_API_KEY and hmac.compare_digest(cleaned, VIEWER_API_KEY):
        if db is not None:
            seeded, principal = _resolve_db_user_principal(db, VIEWER_USERNAME, "api_key")
            if seeded:
                return principal
        return AuthPrincipal(username=VIEWER_USERNAME, role=UserRole.VIEWER, auth_method="api_key")

    # 3. Also accept signed Bearer tokens passed via X-API-Key or Bearer header
    return verify_access_token(cleaned, db=db)


def authenticate_credentials(
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_key: Optional[str] = None,
    db: Optional[Session] = None,
) -> Optional[AuthPrincipal]:
    if api_key and api_key.strip():
        return _match_api_key(api_key, db=db)

    if username is not None and password is not None:
        u = username.strip()
        if not u:
            return None

        def _auth_user_in_session(session: Session) -> Tuple[bool, Optional[AuthPrincipal]]:
            try:
                has_users = session.query(User.id).first() is not None
            except Exception:
                return False, None
            if not has_users:
                return False, None

            user = session.query(User).filter(User.username.ilike(u)).first()
            if user is None or not user.is_active:
                return True, None
            if not verify_password(password, user.password_hash):
                return True, None

            user.last_login_at = utcnow()
            session.commit()
            return True, AuthPrincipal(
                username=user.username,
                role=user.role,
                auth_method="password",
                user_id=user.id,
            )

        if db is not None:
            seeded, principal = _auth_user_in_session(db)
            if seeded:
                return principal
        else:
            try:
                with SessionLocal() as local_db:
                    seeded, principal = _auth_user_in_session(local_db)
                    if seeded:
                        return principal
            except Exception:
                pass

        # Fallback if database has no users seeded
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
    db: Session = Depends(get_db),
) -> Optional[AuthPrincipal]:
    if api_key:
        principal = _match_api_key(api_key, db=db)
        if principal:
            return principal

    if bearer and bearer.scheme.lower() == "bearer" and bearer.credentials:
        principal = _match_api_key(bearer.credentials, db=db)
        if principal:
            return principal

    if basic and basic.username is not None and basic.password is not None:
        principal = authenticate_credentials(username=basic.username, password=basic.password, db=db)
        if principal:
            return principal

    if session_cookie:
        principal = verify_access_token(session_cookie, db=db)
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
