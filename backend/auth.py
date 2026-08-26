from datetime import datetime, timedelta
from typing import Dict, List, Optional
from jose import JWTError, jwt
import bcrypt
import json
import re
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from database import get_db, User, ROLE_SUPER_ADMIN, ROLE_ADMIN, ADMIN_ROLES
import crypto
import request_context
from config import settings

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/token")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


# ── Password policy: min 12 chars, upper, lower, digit, symbol ──
def validate_password(password: str) -> Optional[str]:
    """Return an error string if invalid, else None."""
    if not password or len(password) < 12:
        return "Password must be at least 12 characters."
    if not re.search(r"[A-Z]", password):
        return "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return "Password must contain at least one special character."
    return None


def revoke_tokens(db: Session, user: User):
    """Invalidate every token already issued to this account.

    Called when the account's authority changes. Without it, demoting a super
    admin or resetting a password left the old token working for up to eight
    hours.
    """
    user.tokens_valid_from = datetime.utcnow()
    db.commit()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.utcnow()
    expire = now + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire, "iat": now})
    return jwt.encode(to_encode, crypto.signing_key(settings.SECRET_KEY),
                      algorithm=settings.ALGORITHM)


def get_user(db: Session, username: str) -> Optional[User]:
    return db.query(User).filter(User.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user(db, username)
    if not user or not verify_password(password, user.hashed_password):
        return None
    return user


def _user_from_token(token: str, db: Session) -> User:
    """Resolve and vet a bearer token. Raises 401 if it names an account that
    no longer exists, or was issued before the account's authority changed."""
    exc = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Could not validate credentials",
                        headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, crypto.signing_key(settings.SECRET_KEY),
                             algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise exc
    except JWTError:
        raise exc
    user = get_user(db, username)
    if user is None:
        raise exc
    # A token issued before the account's authority last changed is refused,
    # even though its signature and expiry are still valid.
    if user.tokens_valid_from is not None:
        issued_at = payload.get("iat")
        if issued_at is None:
            raise exc
        try:
            issued = datetime.utcfromtimestamp(int(issued_at))
        except (TypeError, ValueError, OSError):
            raise exc
        if issued < user.tokens_valid_from.replace(microsecond=0):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Your access changed. Please sign in again.",
                headers={"WWW-Authenticate": "Bearer"})
    return user


async def get_current_user(token: str = Depends(oauth2_scheme),
                           db: Session = Depends(get_db)) -> User:
    user = _user_from_token(token, db)
    _touch_last_seen(db, user)
    return user


async def get_current_user_passive(token: str = Depends(oauth2_scheme),
                                   db: Session = Depends(get_db)) -> User:
    """The same checks, without counting as activity.

    For the session heartbeat: it polls only so that a signed-out or deleted
    account stops sitting on a live-looking page. Marking presence from it
    would make every open tab read as somebody at their desk, which is exactly
    what the "Active users" figure is trying not to say.
    """
    return _user_from_token(token, db)


# SQLite takes one writer at a time, so this is throttled rather than written
# on every request. A minute of granularity is far finer than the question it
# answers ("who is signed in right now").
LAST_SEEN_REFRESH_SECONDS = 60

# How long an address stays in `active_ips` before it is dropped. Only there to
# bound the column's growth — callers decide for themselves how recent counts
# as "signed in", and always use a far shorter window than this.
ACTIVE_IP_TTL_SECONDS = 24 * 3600


def load_active_ips(user: User) -> Dict[str, datetime]:
    """The account's {address: last active} map. Unreadable JSON reads as
    empty rather than raising — presence must never fail a request."""
    if not user.active_ips:
        return {}
    try:
        raw = json.loads(user.active_ips)
    except (ValueError, TypeError):
        return {}
    if not isinstance(raw, dict):
        return {}
    seen = {}
    for ip, stamp in raw.items():
        try:
            seen[str(ip)] = datetime.fromisoformat(stamp)
        except (ValueError, TypeError):
            continue
    return seen


def active_ips_since(user: User, cutoff: datetime) -> List[str]:
    """Addresses this account has been active from since `cutoff`, most
    recently used first — one entry per address it is signed in from."""
    seen = load_active_ips(user)
    fresh = [(stamp, ip) for ip, stamp in seen.items() if stamp >= cutoff]
    return [ip for _stamp, ip in sorted(fresh, reverse=True)]


def clear_active_ips(user: User) -> None:
    user.active_ips = None


def _touch_last_seen(db: Session, user: User):
    now = datetime.utcnow()
    ip = request_context.client_ip()
    seen = load_active_ips(user)
    stale = (user.last_seen is None or
             (now - user.last_seen).total_seconds() >= LAST_SEEN_REFRESH_SECONDS)
    # A second session from a new address is written straight away rather than
    # waiting out the throttle: the throttle exists to avoid rewriting a
    # timestamp that has barely moved, not to delay news of a new address.
    new_ip = ip is not None and (
        ip not in seen or
        (now - seen[ip]).total_seconds() >= LAST_SEEN_REFRESH_SECONDS)
    if not stale and not new_ip:
        return
    try:
        user.last_seen = now
        if ip is not None:
            seen[ip] = now
            keep = {addr: stamp.isoformat() for addr, stamp in seen.items()
                    if (now - stamp).total_seconds() < ACTIVE_IP_TTL_SECONDS}
            user.active_ips = json.dumps(keep)
        db.commit()
    except Exception:
        db.rollback()   # Presence is a nicety; it must never fail a request.


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """admin OR super_admin"""
    if current_user.role not in ADMIN_ROLES:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


async def require_super_admin(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role != ROLE_SUPER_ADMIN:
        raise HTTPException(status_code=403, detail="Super admin access required")
    return current_user


# The first-run account. Deliberately trivial and deliberately not printed
# anywhere at runtime — it is written down in the documentation instead, so
# a running server never announces a working credential to whoever can read
# its console or its logs.
DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "admin"


# Passwords that have appeared in the repository or its documentation. Any
# account still using one is reachable by anyone who has read either.
PUBLISHED_PASSWORDS = (DEFAULT_ADMIN_PASSWORD, "Admin@Giga2026!")


def uses_default_admin_password(db: Session) -> bool:
    """Whether the first-run account still has a password that was published."""
    admin = get_user(db, DEFAULT_ADMIN_USERNAME)
    if not admin:
        return False
    return any(verify_password(p, admin.hashed_password)
               for p in PUBLISHED_PASSWORDS)


def ensure_admin_exists(db: Session):
    """Create default super_admin if no users exist; upgrade existing 'admin' to super_admin."""
    if db.query(User).count() == 0:
        u = User(username=DEFAULT_ADMIN_USERNAME,
                 # Bypasses validate_password on purpose: the seeded password
                 # is meant to fail the app's own rules, so it cannot quietly
                 # become a permanent one.
                 hashed_password=get_password_hash(DEFAULT_ADMIN_PASSWORD),
                 role=ROLE_SUPER_ADMIN)
        db.add(u)
        db.commit()
        print("[INIT] Default super admin created. "
              "See the documentation for the sign-in details.")
    else:
        # Promote the original 'admin' account to super_admin
        admin = db.query(User).filter(User.username == "admin").first()
        if admin and admin.role != ROLE_SUPER_ADMIN:
            admin.role = ROLE_SUPER_ADMIN
            db.commit()
            print("[INIT] Existing 'admin' user promoted to super_admin")
