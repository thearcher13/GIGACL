"""
Brute-force protection.

Policy: 3 failed sign-in attempts inside a 5-minute window locks the account
for 5 minutes. The counter resets on a successful sign-in, when the window
expires, or when an administrator unlocks the account.
"""
from datetime import datetime, timedelta
from typing import Optional, Tuple
from sqlalchemy.orm import Session

from database import User

MAX_ATTEMPTS   = 3
WINDOW_MINUTES = 5
LOCK_MINUTES   = 5


def is_locked(user: User) -> Tuple[bool, Optional[int]]:
    """Return (locked, seconds_remaining)."""
    if not user or not user.locked_until:
        return False, None
    now = datetime.utcnow()
    if user.locked_until > now:
        return True, int((user.locked_until - now).total_seconds())
    return False, None


def clear(db: Session, user: User, commit: bool = True):
    """Reset all lockout state for a user."""
    user.failed_attempts = 0
    user.first_failed_at = None
    user.locked_until = None
    if commit:
        db.commit()


def register_failure(db: Session, user: User) -> Tuple[bool, int, int]:
    """
    Record a failed attempt.

    Returns (now_locked, attempts_used, attempts_remaining).
    """
    now = datetime.utcnow()

    # Start a fresh window if there is none or the previous one expired
    if not user.first_failed_at or \
            (now - user.first_failed_at) > timedelta(minutes=WINDOW_MINUTES):
        user.first_failed_at = now
        user.failed_attempts = 0

    user.failed_attempts = (user.failed_attempts or 0) + 1

    if user.failed_attempts >= MAX_ATTEMPTS:
        user.locked_until = now + timedelta(minutes=LOCK_MINUTES)
        db.commit()
        return True, user.failed_attempts, 0

    db.commit()
    return False, user.failed_attempts, MAX_ATTEMPTS - user.failed_attempts


def lock_state(user: User) -> dict:
    """Serialisable lockout status for the user-management UI."""
    locked, secs = is_locked(user)
    return {
        "locked": locked,
        "locked_until": user.locked_until.isoformat() + "Z"
                        if (locked and user.locked_until) else None,
        "seconds_remaining": secs,
        "failed_attempts": user.failed_attempts or 0,
    }


def describe_wait(seconds: Optional[int]) -> str:
    if not seconds or seconds <= 0:
        return "a moment"
    if seconds < 60:
        return f"{seconds} second{'s' if seconds != 1 else ''}"
    mins = (seconds + 59) // 60
    return f"{mins} minute{'s' if mins != 1 else ''}"
