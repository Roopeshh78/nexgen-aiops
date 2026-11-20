"""Authentication, tenant scoping and audit chain."""
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import SECRET_KEY, TOKEN_TTL_MIN
from .db import get_db, utcnow
from .models import AuditLog, User

bearer = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return f"pbkdf2${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
    except ValueError:
        return False
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
    return hmac.compare_digest(candidate, digest)


def create_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "email": user.email,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "name": user.name,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=TOKEN_TTL_MIN),
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status.HTTP_441_EXPECTATION_FAILED if False else 401, "Token expired")
    except jwt.PyJWTError:
        raise HTTPException(401, "Invalid token")


def current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if creds is None:
        raise HTTPException(401, "Missing bearer token")
    claims = decode_token(creds.credentials)
    user = db.get(User, claims["sub"])
    if not user:
        raise HTTPException(401, "User no longer exists")
    return user


def scope_tenant(user: User, requested: str | None) -> str:
    """Tenant separation: a caller may only ever read its own tenant, unless platform_admin."""
    if user.role == "platform_admin":
        return requested or user.tenant_id
    if requested and requested != user.tenant_id:
        raise HTTPException(403, "Cross-tenant access denied")
    return user.tenant_id


def audit(db: Session, tenant_id: str, actor: str, action: str, resource: str = "", detail: dict | None = None):
    prev = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).order_by(AuditLog.id.desc()).first()
    prev_hash = prev.hash if prev else "genesis"
    body = json.dumps({"actor": actor, "action": action, "resource": resource, "detail": detail or {}},
                      sort_keys=True, default=str)
    digest = hashlib.sha256((prev_hash + body).encode()).hexdigest()
    row = AuditLog(tenant_id=tenant_id, actor=actor, action=action, resource=resource,
                   detail=detail or {}, ts=utcnow(), prev_hash=prev_hash, hash=digest)
    db.add(row)
    db.commit()
    return row


def verify_chain(db: Session, tenant_id: str) -> dict:
    rows = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id).order_by(AuditLog.id.asc()).all()
    prev_hash = "genesis"
    for r in rows:
        body = json.dumps({"actor": r.actor, "action": r.action, "resource": r.resource,
                           "detail": r.detail or {}}, sort_keys=True, default=str)
        expected = hashlib.sha256((prev_hash + body).encode()).hexdigest()
        if expected != r.hash:
            return {"valid": False, "broken_at": r.id, "checked": len(rows)}
        prev_hash = r.hash
    return {"valid": True, "checked": len(rows), "head": prev_hash}
