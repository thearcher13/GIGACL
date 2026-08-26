"""
Audit logging helper.
"""
from sqlalchemy.orm import Session
from database import AuditLog
import json
import request_context


def log(db: Session, username: str, message: str,
        description: str = "", level: str = "INFO",
        undo_commands: list = None, undo_label: str = None, switch_id: int = None,
        event_type: str = None, ip_address: str = None):
    """
    Write an audit log entry with optional undo data. Never raises.

    `event_type` is what the dashboard counts by; see the EV_* constants in
    database.py. It is optional and last so existing call sites keep working,
    but every write path should pass one — an untagged row is invisible to the
    activity totals until a backfill guesses at it from the message text.

    `ip_address` defaults to the address the current request came from, so
    every entry records where it originated without each call site repeating
    it. Pass it explicitly only to record an address other than the caller's.
    """
    try:
        # Serialize undo_commands as JSON if provided
        undo_json = json.dumps(undo_commands) if undo_commands else None
        
        entry = AuditLog(
            username=username,
            message=message[:255],
            description=description or "",
            level=level.upper(),
            undo_commands=undo_json,
            undo_label=undo_label,
            switch_id=switch_id,
            event_type=event_type,
            ip_address=ip_address or request_context.client_ip(),
        )
        db.add(entry)
        db.commit()
    except Exception:
        db.rollback()


def log_info(db, username, message, description="", undo_commands=None, undo_label=None,
             switch_id=None, event_type=None, ip_address=None):
    log(db, username, message, description, "INFO", undo_commands, undo_label,
        switch_id, event_type, ip_address)

def log_success(db, username, message, description="", undo_commands=None, undo_label=None,
             switch_id=None, event_type=None, ip_address=None):
    log(db, username, message, description, "SUCCESS", undo_commands, undo_label,
        switch_id, event_type, ip_address)

def log_warn(db, username, message, description="", undo_commands=None, undo_label=None,
             switch_id=None, event_type=None, ip_address=None):
    log(db, username, message, description, "WARN", undo_commands, undo_label,
        switch_id, event_type, ip_address)

def log_error(db, username, message, description="", undo_commands=None, undo_label=None,
             switch_id=None, event_type=None, ip_address=None):
    log(db, username, message, description, "ERROR", undo_commands, undo_label,
        switch_id, event_type, ip_address)
