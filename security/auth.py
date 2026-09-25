"""
security/auth.py
================
Role-Based Access Control (RBAC) & Cryptographic Session Authentication.

Provides:
  - Database-backed defense operator authentication & credential verification
  - Zero-dependency PBKDF2-HMAC-SHA256 password hashing & constant-time validation
  - Default account seeding into SQLite User table
  - Cryptographically secure HMAC-SHA256 bearer session tokens
  - Role hierarchy: COMMANDER > OPERATOR > ANALYST
  - FastAPI dependency injection for role validation and clearance enforcement
"""

import hmac
import hashlib
import base64
import json
import time
import secrets
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from fastapi import HTTPException, Security, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from utils.logger import logger

SECRET_KEY = "SIH_BORDER_SURVEILLANCE_CLASSIFIED_DEFENSE_TOKEN_KEY"

# Pre-configured demonstration operational accounts
USERS_DB = {
    "commander": {
        "callsign": "CDR. Vikram Singh",
        "username": "commander",
        "password": "cmd@border2024",
        "role": "COMMANDER",
        "clearance": "Level 5 (Top Secret)",
        "station": "Northern Frontier C2 HQ",
    },
    "operator": {
        "callsign": "OPR. Rajesh Kumar",
        "username": "operator",
        "password": "op@patrol2024",
        "role": "OPERATOR",
        "clearance": "Level 3 (Operational)",
        "station": "Outpost Alpha-1",
    },
    "analyst": {
        "callsign": "ANL. Priya Sharma",
        "username": "analyst",
        "password": "audit@sih2024",
        "role": "ANALYST",
        "clearance": "Level 4 (Forensic Audit)",
        "station": "Intelligence Wing",
    },
}

# Role permissions hierarchy
ROLE_PERMISSIONS = {
    "COMMANDER": ["live_view", "alert_triage", "zone_manage", "tamper_control", "audit_view", "export_dossier", "admin"],
    "OPERATOR": ["live_view", "alert_triage", "zone_create", "anpr_lookup", "export_dossier"],
    "ANALYST": ["live_view", "historical_search", "audit_view", "export_dossier", "blockchain_verify"],
}

security_bearer = HTTPBearer(auto_error=False)


# ── Password Hashing & Verification (Zero-Dependency PBKDF2-HMAC-SHA256) ─────

def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Generate salted PBKDF2-HMAC-SHA256 password hash."""
    if not salt:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return pw_hash, salt


def verify_password(password: str, password_hash: str, salt: str) -> bool:
    """Verify password against stored PBKDF2 hash using constant-time comparison."""
    calc_hash, _ = hash_password(password, salt)
    return hmac.compare_digest(calc_hash, password_hash)


# ── Database Account Seeding ────────────────────────────────────────────────

def seed_default_users(session) -> int:
    """
    Ensure the standard defense operational accounts exist in the SQLite User table.
    Returns the number of seeded accounts.
    """
    from database.models import User
    try:
        seeded = 0
        for uname, data in USERS_DB.items():
            existing = session.query(User).filter(User.username == uname).first()
            if not existing:
                pw_hash, salt = hash_password(data["password"])
                new_user = User(
                    username=uname,
                    password_hash=pw_hash,
                    salt=salt,
                    callsign=data["callsign"],
                    role=data["role"],
                    clearance=data["clearance"],
                    station=data["station"],
                    is_active=True,
                    created_at=datetime.utcnow(),
                )
                session.add(new_user)
                seeded += 1
        if seeded > 0:
            session.commit()
            logger.info(f"Seeded {seeded} operational defense accounts into User table.")
        return seeded
    except Exception as e:
        logger.warning(f"Error seeding defense users: {e}")
        return 0


# ── User Registration ───────────────────────────────────────────────────────

def register_user(
    username: str,
    password: str,
    callsign: str,
    role: str = "OPERATOR",
    clearance: str = "Level 3 (Operational)",
    station: str = "Northern Frontier C2 HQ"
) -> Dict[str, Any]:
    """Register a new defense operator profile in the database."""
    from database.db import get_db
    from database.models import User

    norm_user = username.strip().lower()
    pw_hash, salt = hash_password(password)

    with get_db() as session:
        existing = session.query(User).filter(User.username == norm_user).first()
        if existing:
            raise ValueError(f"User '{username}' already exists.")
        user = User(
            username=norm_user,
            password_hash=pw_hash,
            salt=salt,
            callsign=callsign,
            role=role.upper(),
            clearance=clearance,
            station=station,
            is_active=True,
            created_at=datetime.utcnow(),
        )
        session.add(user)
        session.flush()
        return user.to_dict()


# ── Token Encoding & Decoding ───────────────────────────────────────────────

def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64_decode(data: str) -> bytes:
    padding = 4 - (len(data) % 4)
    if padding < 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_access_token(payload: Dict[str, Any], expires_in: int = 86400) -> str:
    """Generate cryptographically signed HMAC-SHA256 session token."""
    header = {"alg": "HS256", "typ": "JWT"}
    body = {
        **payload,
        "exp": int(time.time()) + expires_in,
        "iat": int(time.time()),
    }
    hdr_b64 = _b64_encode(json.dumps(header).encode())
    body_b64 = _b64_encode(json.dumps(body).encode())
    signing_input = f"{hdr_b64}.{body_b64}".encode()
    signature = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_encode(signature)
    return f"{hdr_b64}.{body_b64}.{sig_b64}"


def verify_token(token: str) -> Optional[Dict[str, Any]]:
    """Validate token signature and expiration."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        hdr_b64, body_b64, sig_b64 = parts
        signing_input = f"{hdr_b64}.{body_b64}".encode()
        expected_sig = hmac.new(SECRET_KEY.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_decode(sig_b64), expected_sig):
            return None
        payload = json.loads(_b64_decode(body_b64).decode())
        if payload.get("exp", 0) < time.time():
            return None
        return payload
    except Exception as e:
        logger.warning(f"Token verification error: {e}")
        return None


# ── Authentication ──────────────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate against the SQLite database User table.
    Falls back gracefully to pre-configured USERS_DB dictionary if needed.
    """
    norm_user = username.strip().lower()

    # 1. Primary: Database Authentication
    try:
        from database.db import get_db
        from database.models import User

        with get_db() as session:
            db_user = session.query(User).filter(User.username == norm_user).first()
            if db_user and db_user.is_active:
                if verify_password(password, db_user.password_hash, db_user.salt):
                    db_user.last_login = datetime.utcnow()
                    session.commit()
                    return {
                        "id": db_user.id,
                        "username": db_user.username,
                        "callsign": db_user.callsign,
                        "role": db_user.role,
                        "clearance": db_user.clearance,
                        "station": db_user.station,
                    }
    except Exception as e:
        logger.warning(f"Database authentication query error: {e}")

    # 2. Fallback: Pre-configured dictionary
    user = USERS_DB.get(norm_user)
    if user and user["password"] == password:
        profile = dict(user)
        del profile["password"]
        return profile

    return None


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer),
) -> Dict[str, Any]:
    """
    Extract authenticated user from Authorization Bearer token.
    Falls back to Commander demo mode if no token provided for open development.
    """
    if credentials and credentials.credentials:
        payload = verify_token(credentials.credentials)
        if payload:
            return payload

    # Default fallback user for open presentation if no Bearer header is attached
    return {
        "username": "commander",
        "callsign": "CDR. Vikram Singh (Demo Mode)",
        "role": "COMMANDER",
        "clearance": "Level 5 (Top Secret)",
        "station": "Northern Frontier C2 HQ",
    }


def require_role(allowed_roles: List[str]):
    """FastAPI dependency factory to enforce RBAC permissions."""
    async def role_checker(user: Dict[str, Any] = Depends(get_current_user)):
        user_role = user.get("role", "OPERATOR")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Action requires one of roles: {allowed_roles}. Current role: {user_role}",
            )
        return user
    return role_checker
