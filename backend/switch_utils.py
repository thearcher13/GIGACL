"""
Shared switch utilities to avoid circular imports.
"""
from fastapi import HTTPException
from sqlalchemy.orm import Session
from typing import Optional
from database import Switch
import crypto


def encrypt_password(password: str) -> str:
    from config import settings
    return crypto.encrypt_password(settings.SECRET_KEY, password)


def decrypt_password(token: str) -> str:
    """Reads values written under the previous scheme too, so a database that
    predates the key change keeps working."""
    from config import settings
    return crypto.decrypt_password(settings.SECRET_KEY, token)


def get_switch_and_password(
    switch_id: int,
    username: str,
    provided_password: Optional[str],
    db: Session
):
    """
    Return (Switch, ssh_password_str, enable_password_str).
    Enable password is None if use_enable=False or not saved.
    Raises HTTPException on errors.
    """
    switch = db.query(Switch).filter(
        Switch.id == switch_id,
        Switch.owner_username == username
    ).first()
    if not switch:
        raise HTTPException(status_code=404, detail="Switch not found")

    password = provided_password
    if not password:
        if switch.saved_password:
            password = decrypt_password(switch.saved_password)
        else:
            raise HTTPException(
                status_code=400,
                detail="SSH password required. No saved password for this switch."
            )
    
    # Get enable password if needed
    enable_password = None
    if switch.use_enable and switch.saved_enable_password:
        enable_password = decrypt_password(switch.saved_enable_password)
    
    return switch, password, enable_password
