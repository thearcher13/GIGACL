"""
Audit log retention: deleting old entries, optionally backed up as a zip
first. Replaces the old, unconfigurable audit.cleanup_old_logs — this one
reads its cutoff from AppSettings instead of a hardcoded constant, and can
run either on demand (a super admin clicking "Delete Now") or on a schedule
(the background sweep started in main.py's startup handler).
"""
import csv
import io
import os
import zipfile
from datetime import datetime, timedelta
from typing import List

from sqlalchemy.orm import Session

from database import AuditLog, get_app_settings
import audit

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "log_backups")

CSV_COLUMNS = ("timestamp", "level", "username", "ip_address", "message",
               "description", "switch_id", "event_type")


def rows_older_than(db: Session, days: int) -> List[AuditLog]:
    cutoff = datetime.utcnow() - timedelta(days=days)
    return db.query(AuditLog).filter(AuditLog.timestamp < cutoff)\
                             .order_by(AuditLog.timestamp).all()


def build_zip(rows: List[AuditLog]) -> bytes:
    """One CSV of the rows being removed, zipped. Built in memory — retention
    exports are occasional and bounded by the log table's own size, not worth
    a temp file."""
    csv_buf = io.StringIO()
    writer = csv.writer(csv_buf)
    writer.writerow(CSV_COLUMNS)
    for r in rows:
        writer.writerow([
            r.timestamp.isoformat() if r.timestamp else "",
            r.level, r.username, r.ip_address or "", r.message,
            r.description or "",
            r.switch_id if r.switch_id is not None else "",
            r.event_type or "",
        ])

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("audit_logs_backup.csv", csv_buf.getvalue())
    return zip_buf.getvalue()


def delete_rows(db: Session, rows: List[AuditLog]) -> int:
    count = len(rows)
    for r in rows:
        db.delete(r)
    db.commit()
    return count


def run_scheduled_cleanup(db: Session) -> dict:
    """Called periodically by the background sweep. No-ops unless auto-delete
    is enabled; safe to call repeatedly since deletion is idempotent."""
    settings = get_app_settings(db)
    settings.log_retention_last_run = datetime.utcnow()
    if settings.log_auto_delete_days <= 0:
        db.commit()
        return {"deleted": 0}

    rows = rows_older_than(db, settings.log_auto_delete_days)
    if not rows:
        db.commit()
        return {"deleted": 0}

    saved_to = None
    if settings.log_auto_delete_zip:
        saved_to = save_backup_to_disk(build_zip(rows))

    deleted = delete_rows(db, rows)
    db.commit()
    audit.log_info(db, "system", f"Auto-deleted {deleted} old audit log(s)",
                   f"Scheduled sweep removed entries older than "
                   f"{settings.log_auto_delete_days} day(s). "
                   + (f"Backup saved to {saved_to}." if saved_to
                      else "No backup was kept."))
    return {"deleted": deleted, "backup_path": saved_to}


def save_backup_to_disk(zip_bytes: bytes) -> str:
    """Keep a copy under backend/log_backups/. Used by the scheduled sweep,
    and by a manual delete that asked for a zip -- the operator gets the
    download and the project keeps its own copy."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(BACKUP_DIR, f"audit_logs_backup_{stamp}.zip")
    with open(path, "wb") as f:
        f.write(zip_bytes)
    return path
