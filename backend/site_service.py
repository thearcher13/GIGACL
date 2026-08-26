"""
Location label management.

Built-in labels are shared by everyone; each user can also define their own.
"""
import re
from typing import List
from sqlalchemy.orm import Session

from database import SiteLabel, Switch, BUILTIN_SITES
from validators import ValidationError, check_cli_safe

MAX_CUSTOM_SITES = 40
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _\-\.]{0,31}$")


def normalise(name: str) -> str:
    """Canonical form used for storage and comparison."""
    return re.sub(r"\s+", " ", (name or "").strip()).lower()


def validate_new_label(name: str) -> str:
    raw = check_cli_safe(name or "", "Location name")
    if not raw:
        raise ValidationError("Enter a name for the location.")
    if not _NAME_RE.match(raw):
        raise ValidationError(
            "Location names may use letters, digits, spaces, dot, dash or "
            "underscore (max 32 characters) and must start with a letter or digit."
        )
    return normalise(raw)


def custom_labels(db: Session, username: str) -> List[str]:
    rows = db.query(SiteLabel).filter(
        SiteLabel.owner_username == username,
        SiteLabel.hidden.is_(False)).all()
    return sorted({r.name for r in rows})


def hidden_builtins(db: Session, username: str) -> List[str]:
    """Built-in labels this user has removed from their own list."""
    rows = db.query(SiteLabel).filter(
        SiteLabel.owner_username == username,
        SiteLabel.hidden.is_(True)).all()
    return sorted({r.name for r in rows if r.name in BUILTIN_SITES})


def all_labels(db: Session, username: str) -> List[str]:
    """Built-ins first (in their defined order), then the user's own, alphabetically.
    Built-ins this user has hidden are left out."""
    hidden = set(hidden_builtins(db, username))
    custom = [c for c in custom_labels(db, username) if c not in BUILTIN_SITES]
    return [b for b in BUILTIN_SITES if b not in hidden] + custom


def _unassign_switches(db: Session, username: str, value: str) -> int:
    affected = db.query(Switch).filter(
        Switch.owner_username == username, Switch.site == value).all()
    for s in affected:
        s.site = None
    return len(affected)


def add_label(db: Session, username: str, name: str) -> str:
    value = validate_new_label(name)
    existing = db.query(SiteLabel).filter(
        SiteLabel.owner_username == username, SiteLabel.name == value).first()
    if value in BUILTIN_SITES:
        # Re-adding a built-in is how a user restores one they hid earlier.
        if existing is not None and existing.hidden:
            existing.hidden = False
            db.commit()
            return value
        raise ValidationError(f"'{value}' is already a built-in location.")
    if existing is not None and not existing.hidden:
        raise ValidationError(f"You already have a location called '{value}'.")
    if len(custom_labels(db, username)) >= MAX_CUSTOM_SITES:
        raise ValidationError(
            f"You have reached the limit of {MAX_CUSTOM_SITES} custom locations.")
    db.add(SiteLabel(name=value, owner_username=username))
    db.commit()
    return value


def delete_label(db: Session, username: str, name: str) -> int:
    """Remove a label from this user's list. Custom labels are deleted; a
    built-in is shared with everyone, so it is only hidden for this user.
    Returns how many of their switches were un-assigned."""
    value = normalise(name)
    if value in BUILTIN_SITES:
        if value in hidden_builtins(db, username):
            raise ValidationError(f"'{value}' is already removed from your list.")
        freed = _unassign_switches(db, username, value)
        row = db.query(SiteLabel).filter(
            SiteLabel.owner_username == username, SiteLabel.name == value).first()
        if row is None:
            row = SiteLabel(name=value, owner_username=username, hidden=True)
            db.add(row)
        else:
            row.hidden = True
        db.commit()
        return freed
    row = db.query(SiteLabel).filter(
        SiteLabel.owner_username == username, SiteLabel.name == value,
        SiteLabel.hidden.is_(False)).first()
    if not row:
        raise ValidationError(f"You do not have a location called '{value}'.")
    freed = _unassign_switches(db, username, value)
    db.delete(row)
    db.commit()
    return freed


def validate_site_for_user(db: Session, username: str, value) -> str:
    """Validate a site value submitted for a switch. Empty means unassigned."""
    if value is None or not str(value).strip():
        return None
    v = normalise(check_cli_safe(str(value), "Location"))
    allowed = all_labels(db, username)
    if v not in allowed:
        raise ValidationError(
            f"Location '{value}' is not one of your locations. "
            f"Add it first in Manage Switches, or pick an existing one."
        )
    return v
