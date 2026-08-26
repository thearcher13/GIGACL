from sqlalchemy import (create_engine, Column, Integer, String, Boolean,
                        DateTime, Text, Float)
from sqlalchemy.orm import sessionmaker, declarative_base
from datetime import datetime
from config import settings

engine = create_engine(settings.DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ── Roles ──
ROLE_USER        = "user"
ROLE_ADMIN       = "admin"
ROLE_SUPER_ADMIN = "super_admin"
ALL_ROLES   = (ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN)
ADMIN_ROLES = (ROLE_ADMIN, ROLE_SUPER_ADMIN)

# ── Per-switch access ──
# A switch row granted by a super admin can be read-only: the holder may run
# every analysis but cannot open a terminal or change anything on the device.
ACCESS_READ  = "read"
ACCESS_WRITE = "write"
ALL_ACCESS   = (ACCESS_READ, ACCESS_WRITE)

# ── Switch types ──
TYPE_IOS   = "ios"
TYPE_NEXUS = "nexus"
ALL_TYPES  = (TYPE_IOS, TYPE_NEXUS)

# ── Sites / locations (built-in defaults; users can add their own) ──
BUILTIN_SITES = ["site1", "site2", "site3", "site5", "site6",
                 "part", "part2", "part3", "part5", "part6"]
# Backwards-compatible alias
SITES = BUILTIN_SITES


class User(Base):
    __tablename__ = "users"
    id              = Column(Integer, primary_key=True, index=True)
    username        = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(128), nullable=False)
    role            = Column(String(20), nullable=False, default=ROLE_USER)
    created_at      = Column(DateTime, default=datetime.utcnow)
    # ── brute-force lockout ──
    failed_attempts = Column(Integer, default=0)
    first_failed_at = Column(DateTime, nullable=True)
    locked_until    = Column(DateTime, nullable=True)
    # ── trusted hosts (comma-separated IP prefixes) ──
    trusted_hosts   = Column(Text, nullable=True)
    # Per-account ordering for location labels and switches in both switch
    # management and the active-switch picker (JSON payload).
    switch_layout   = Column(Text, nullable=True)
    # Personal animated mascot selected by the account owner. The persisted
    # column keeps its original name so existing development databases migrate
    # without losing a user's choice.
    mega            = Column("maga", String(32), nullable=False, default="byte")
    # Off for a new account. The mascot is opt-in rather than something a new
    # user has to discover how to dismiss.
    mega_visible    = Column(Boolean, nullable=False, default=False)
    # Colour scheme, chosen by the account owner. Stored here rather than in
    # localStorage so the choice follows the person between browsers, exactly
    # as `mega` does. The two original schemes keep their ids -- 'dark' and
    # 'light' -- so a browser that already carries one migrates into the
    # column without the user's colours moving.
    theme           = Column(String(32), nullable=False, default="dark")
    # Tokens issued before this moment are refused. Bumped whenever the
    # account's authority changes — a role downgrade or a password reset
    # otherwise stayed ineffective until the 8-hour token expired.
    tokens_valid_from = Column(DateTime, nullable=True)
    # JSON {ip: last-seen ISO timestamp} of the addresses this account has been
    # active from. `last_seen` alone cannot say that somebody is signed in from
    # two places at once; this can.
    active_ips        = Column(Text, nullable=True)
    # Touched by get_current_user, so the dashboard can say who is signed in
    # right now. There is no session store — a token stays valid until it
    # expires — so recent traffic is the only evidence of presence there is.
    last_seen       = Column(DateTime, nullable=True)


class Switch(Base):
    __tablename__ = "switches"
    id             = Column(Integer, primary_key=True, index=True)
    ip_address     = Column(String(64), nullable=False)
    hostname       = Column(String(128), nullable=True)
    switch_type    = Column(String(32), nullable=True, default=TYPE_IOS)
    site           = Column(String(64), nullable=True)
    owner_username = Column(String(64), nullable=False, index=True)
    saved_password = Column(Text, nullable=True)
    saved_enable_password = Column(Text, nullable=True)  # Encrypted enable password when use_enable=True
    use_enable     = Column(Boolean, default=False)
    ssh_username   = Column(String(64), nullable=True)  # SSH username for this switch
    vpc_peer_id    = Column(Integer, nullable=True)
    # True when running-config has been modified but not yet copied to startup-config
    pending_changes = Column(Boolean, default=False)
    # Set when a super admin added this switch on someone else's behalf. The
    # holder cannot edit or delete such a row; only the granter can. Empty for
    # a switch someone added for themselves.
    created_by     = Column(String(64), nullable=True, index=True)
    access_level   = Column(String(16), nullable=False, default=ACCESS_WRITE)
    # Whether the holder may open an interactive SSH terminal to it. A terminal
    # is unrestricted access to the device, so read-only has never included one
    # — this narrows write access without dropping it to read.
    terminal_access = Column(Boolean, nullable=False, default=True)
    created_at     = Column(DateTime, default=datetime.utcnow)


class SiteLabel(Base):
    """A user-defined location label, in addition to the built-in ones.

    A row with hidden=True means the opposite: it marks one of the shared
    built-in labels as removed *for this user only*, so everyone else keeps
    it. Built-ins have no rows of their own to delete, so hiding is how a
    per-user removal is recorded.
    """
    __tablename__ = "site_labels"
    id             = Column(Integer, primary_key=True, index=True)
    name           = Column(String(64), nullable=False)
    owner_username = Column(String(64), nullable=False, index=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    hidden         = Column(Boolean, nullable=False, default=False)


class Template(Base):
    """A reusable, server-side (not switch-config) block of ACL rule
    lines, personal to its owner unless shared. `lines` and
    `reversed_lines` are each a JSON-encoded list[str] of bare rule text
    (no sequence numbers) — `direction` records which one `lines` was
    authored for; `reversed_lines` is auto-derived from it."""
    __tablename__ = "templates"
    id             = Column(Integer, primary_key=True, index=True)
    name           = Column(String(64), nullable=False)
    owner_username = Column(String(64), nullable=False, index=True)
    switch_type    = Column(String(32), nullable=False)
    acl_kind       = Column(String(16), nullable=False, default="extended")
    direction      = Column(String(8), nullable=False)
    lines          = Column(Text, nullable=False)
    reversed_lines = Column(Text, nullable=False)
    skipped_reversal_count = Column(Integer, nullable=False, default=0)
    created_at     = Column(DateTime, default=datetime.utcnow)
    updated_at     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class TemplateShare(Base):
    """One row per (template, username) a template has been shared with."""
    __tablename__ = "template_shares"
    id          = Column(Integer, primary_key=True, index=True)
    template_id = Column(Integer, nullable=False, index=True)
    username    = Column(String(64), nullable=False, index=True)


class AppSettings(Base):
    """Single-row table for app-wide settings shared by every user."""
    __tablename__ = "app_settings"
    id                    = Column(Integer, primary_key=True, index=True)
    # Minutes of inactivity before the UI auto-logs a user out. 0 = never.
    idle_timeout_minutes  = Column(Integer, nullable=False, default=0)
    # Days of retention before the scheduled sweep deletes audit logs. 0 = never.
    log_auto_delete_days   = Column(Integer, nullable=False, default=0)
    log_auto_delete_zip    = Column(Boolean, nullable=False, default=False)
    log_retention_last_run = Column(DateTime, nullable=True)


def get_app_settings(db) -> "AppSettings":
    """Get-or-create the single AppSettings row."""
    row = db.query(AppSettings).first()
    if row is None:
        row = AppSettings(idle_timeout_minutes=0)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id          = Column(Integer, primary_key=True, index=True)
    timestamp   = Column(DateTime, default=datetime.utcnow, index=True)
    level       = Column(String(16), nullable=False, default="INFO")
    username    = Column(String(64), nullable=False, index=True)
    message     = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    # Undo support: store commands, label, and switch_id for reversible operations
    undo_commands = Column(Text, nullable=True)
    undo_label    = Column(String(255), nullable=True)
    switch_id     = Column(Integer, index=True, nullable=True)
    # Where the request came from. Recorded for every entry, not just sign-ins,
    # so an audit trail can answer "from where" as well as "who".
    ip_address    = Column(String(64), nullable=True)
    # Structured category for the dashboard. Message text is for humans and is
    # reworded freely; counting on it would break silently, so writes record
    # what happened here instead. Older rows are classified once at migration.
    event_type    = Column(String(32), index=True, nullable=True)


# ── Audit event types ──
# Defined here rather than in audit.py because the migration below needs them
# and audit.py already imports from this module.
EV_RULE_ADD       = "rule_add"
EV_RULE_DELETE    = "rule_delete"
EV_RULE_EDIT      = "rule_edit"
EV_ACL_CREATE     = "acl_create"
EV_ACL_DELETE     = "acl_delete"
EV_ACL_BINDING    = "acl_binding"
EV_SUMMARY_APPLY  = "summary_apply"
EV_TEMPLATE_APPLY = "template_apply"
EV_REVERSE_APPLY  = "reverse_apply"
EV_OBJECT_GROUP   = "object_group"
EV_TIME_RANGE     = "time_range"
EV_UNDO           = "undo"
EV_CONFIG_SAVE    = "config_save"
EV_WRITE_FAILED   = "write_failed"
EV_SWITCH_ADMIN   = "switch_admin"
EV_USER_ADMIN     = "user_admin"
EV_LOGIN          = "login"
EV_LOGIN_FAILED   = "login_failed"
EV_ANALYSIS       = "analysis"
EV_TERMINAL       = "terminal"

# What the dashboard counts as "a change to a switch". Reads and admin actions
# are deliberately excluded — this is the number an operator cares about.
WRITE_EVENT_TYPES = (
    EV_RULE_ADD, EV_RULE_DELETE, EV_RULE_EDIT, EV_ACL_CREATE, EV_ACL_DELETE,
    EV_ACL_BINDING, EV_SUMMARY_APPLY, EV_TEMPLATE_APPLY, EV_REVERSE_APPLY,
    EV_OBJECT_GROUP, EV_TIME_RANGE, EV_UNDO,
)

# Message prefixes for rows written before event_type existed. Order matters:
# 'Failed to' is listed first so a failure is never claimed by the prefix of
# the action it failed at.
LEGACY_EVENT_PREFIXES = (
    (EV_WRITE_FAILED,   ("Failed to", "Undo failed on", "Could not add switch",
                         "Error applying", "SSH error while")),
    (EV_RULE_ADD,       ("Added a rule to", "Added an ACL remark to")),
    (EV_RULE_DELETE,    ("Deleted rule ",)),
    (EV_RULE_EDIT,      ("Edited rule ",)),
    (EV_ACL_CREATE,     ("Created ACL ",)),
    (EV_ACL_DELETE,     ("Deleted ACL ",)),
    (EV_ACL_BINDING,    ("Applied ACL ", "Removed ACL ", "Moved ACL ")),
    (EV_SUMMARY_APPLY,  ("Applied a summary rule to",)),
    (EV_TEMPLATE_APPLY, ("Applied template ",)),
    (EV_REVERSE_APPLY,  ("Reversed direction of",)),
    (EV_OBJECT_GROUP,   ("Created address object group", "Created port object group",
                         "Added a member to object group",
                         "Deleted a member from object group",
                         "Edited a member of object group",
                         "Deleted object group")),
    # 'Applied'/'Edited' are older wordings this code no longer produces.
    (EV_TIME_RANGE,     ("Created time-range", "Updated time-range",
                         "Deleted time-range", "Applied time-range",
                         "Edited time-range")),
    (EV_UNDO,           ("Undid",)),
    (EV_CONFIG_SAVE,    ("Saved configuration on",)),
    (EV_SWITCH_ADMIN,   ("Added switch", "Updated switch", "Removed switch",
                         "Paired VPC", "Unpaired VPC",
                         "Added location", "Deleted location",
                         "Created template", "Updated template", "Deleted template")),
    (EV_USER_ADMIN,     ("Created user", "Deleted user", "Changed role of",
                         "Reset password for", "Unlocked account",
                         "Changed own password", "Password change rejected",
                         "Updated trusted hosts", "Updated own trusted hosts",
                         "Changed idle logout timeout", "Cleaned up")),
    (EV_LOGIN,          ("Signed in", "User logged in")),
    (EV_LOGIN_FAILED,   ("Failed login attempt", "Sign-in blocked",
                         "Account locked")),
    (EV_ANALYSIS,       ("Redundancy check", "Summary suggestions",
                         "VPC sync check", "Looked up ACLs for",
                         "Generated an access report", "Access check",
                         "Checked access", "Global IP ACL lookup")),
    (EV_TERMINAL,       ("Closed interactive terminal", "Interactive terminal ended",
                         "Opened interactive terminal")),
)


# ── Fleet health snapshot ──
# Health checks need SSH, so the dashboard never runs them on page load. A sweep
# writes one row per switch here and the dashboard reads only this table.
HEALTH_OK             = "ok"
HEALTH_PARTIAL        = "partial"
HEALTH_ERROR          = "error"
HEALTH_NO_CREDENTIALS = "no_credentials"

TCAM_OK          = "ok"
TCAM_UNSUPPORTED = "unsupported"


class SwitchHealth(Base):
    """Latest sweep result for one switch. Counts only — never rule detail."""
    __tablename__ = "switch_health"
    id           = Column(Integer, primary_key=True, index=True)
    switch_id    = Column(Integer, nullable=False, unique=True, index=True)
    collected_at = Column(DateTime, default=datetime.utcnow, index=True)
    scanned_by   = Column(String(64), nullable=True)
    duration_ms  = Column(Integer, nullable=True)
    status       = Column(String(16), nullable=False, default=HEALTH_OK)
    error        = Column(Text, nullable=True)

    acl_count                = Column(Integer, nullable=False, default=0)
    rule_count               = Column(Integer, nullable=False, default=0)
    object_group_count       = Column(Integer, nullable=False, default=0)
    # Kept apart rather than summed: the two redundancy passes can flag the
    # same rule, and check_redundant_rules groups by covering rule.
    redundant_count          = Column(Integer, nullable=False, default=0)
    trailing_redundant_count = Column(Integer, nullable=False, default=0)
    wrong_direction_count    = Column(Integer, nullable=False, default=0)
    summarizable_count       = Column(Integer, nullable=False, default=0)
    summary_suggestion_count = Column(Integer, nullable=False, default=0)
    time_ranges_total        = Column(Integer, nullable=False, default=0)
    time_ranges_inactive     = Column(Integer, nullable=False, default=0)
    time_ranges_expired      = Column(Integer, nullable=False, default=0)
    rules_with_dead_schedule = Column(Integer, nullable=False, default=0)

    vpc_peer_id       = Column(Integer, nullable=True)
    vpc_sync_status   = Column(String(16), nullable=True)
    # Split so the dashboard can say which half differs: ACLs whose rules
    # differ, and ACLs applied to different VLANs or in different directions.
    vpc_mismatch_count = Column(Integer, nullable=True)
    vpc_binding_mismatch_count = Column(Integer, nullable=True)

    tcam_status   = Column(String(16), nullable=False, default=TCAM_UNSUPPORTED)
    # When this disagrees with the switch's configured type, the switch is
    # mislabelled — the only validation the app has for that field.
    tcam_source   = Column(String(16), nullable=True)
    tcam_error    = Column(Text, nullable=True)
    tcam_max      = Column(Integer, nullable=True)
    tcam_in_used  = Column(Integer, nullable=True)
    tcam_in_free  = Column(Integer, nullable=True)
    tcam_in_pct   = Column(Float, nullable=True)
    tcam_out_used = Column(Integer, nullable=True)
    tcam_out_free = Column(Integer, nullable=True)
    tcam_out_pct  = Column(Float, nullable=True)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()



# ── access requests ───────────────────────────────────────────────────────
REQUEST_PENDING   = "pending"
REQUEST_GRANTED   = "granted"
REQUEST_REJECTED  = "rejected"
REQUEST_CANCELLED = "cancelled"


class AccessRequest(Base):
    """
    Somebody without write access asking an admin to open a path.

    Raised from the Access Checker, when a check comes back denied and the
    switch itself is the thing denying it -- so the request always names a
    specific switch, a specific direction, and the rule that blocked it. That
    context is the whole value: an admin should be able to act on one of these
    without going and re-running the check themselves.

    The switch is recorded by id and by name and address, because the id is
    only meaningful to accounts that hold that switch. An admin who was never
    granted it still needs to read the request and understand what it is
    about, even though they cannot act on it.
    """
    __tablename__ = "access_requests"
    id                 = Column(Integer, primary_key=True, index=True)
    requester_username = Column(String(64), nullable=False, index=True)
    created_at         = Column(DateTime, default=datetime.utcnow, index=True)

    switch_id    = Column(Integer, nullable=True, index=True)
    switch_ip    = Column(String(64), nullable=True)
    switch_label = Column(String(128), nullable=True)

    # The access-check fields, verbatim, so approving one can seed Add Rule
    # with exactly what was asked for rather than an approximation.
    src_ip    = Column(String(64), nullable=False)
    dst_ip    = Column(String(64), nullable=False)
    protocol  = Column(String(16), nullable=False, default="all")
    port      = Column(String(32), nullable=True)
    icmp_type = Column(String(32), nullable=True)

    # Why the requester believes it is blocked here: which side, on which
    # interface, by which rule in which ACL.
    denied_side   = Column(String(16), nullable=True)
    vlan          = Column(String(64), nullable=True)
    acl_name      = Column(String(128), nullable=True)
    matched_rule  = Column(Text, nullable=True)

    remark = Column(Text, nullable=True)

    status          = Column(String(16), nullable=False,
                             default=REQUEST_PENDING, index=True)
    resolved_at     = Column(DateTime, nullable=True)
    resolved_by     = Column(String(64), nullable=True)
    resolution_note = Column(Text, nullable=True)
    # Drives the "your request was answered" toast on the requester's next
    # load. Set when an admin resolves it, cleared once they have looked.
    seen_by_requester = Column(Boolean, nullable=False, default=False)

def init_db():
    Base.metadata.create_all(bind=engine)
    _run_migrations()
    _restrict_database_permissions()


def _restrict_database_permissions():
    """Keep the database readable only by the account running the app.

    It holds every switch credential, encrypted — but an encrypted secret in
    a world-readable file is one stolen key away from being plaintext.
    """
    import os
    url = settings.DATABASE_URL
    if not url.startswith("sqlite:///"):
        return
    path = url[len("sqlite:///"):]
    if path in (":memory:", ""):
        return
    try:
        if os.path.exists(path):
            os.chmod(path, 0o600)
    except OSError as e:
        print(f"[SECURITY] Could not restrict permissions on {path}: {e}")


_column_was_added = {}


def _run_migrations():
    """Add columns that may be missing from an older SQLite file."""
    from sqlalchemy import text
    _column_was_added.clear()
    wanted = {
        "switches": {
            "site":            "VARCHAR(64)",
            "vpc_peer_id":     "INTEGER",
            "use_enable":      "BOOLEAN DEFAULT 0",
            "saved_enable_password": "TEXT",
            "switch_type":     "VARCHAR(32)",
            "pending_changes": "BOOLEAN DEFAULT 0",
            "ssh_username":    "VARCHAR(64)",
            "created_by":      "VARCHAR(64)",
            "access_level":    "VARCHAR(16) NOT NULL DEFAULT 'write'",
            # Defaults on: every write grant that predates the column had a
            # terminal, and taking it away silently would be a regression.
            "terminal_access": "BOOLEAN NOT NULL DEFAULT 1",
        },
        "users": {
            "failed_attempts": "INTEGER DEFAULT 0",
            "first_failed_at": "DATETIME",
            "locked_until":    "DATETIME",
            "trusted_hosts":   "TEXT",
            "switch_layout":   "TEXT",
            "maga":            "VARCHAR(32) NOT NULL DEFAULT 'byte'",
            "last_seen":       "DATETIME",
            "mega_visible":    "BOOLEAN NOT NULL DEFAULT 0",
            "theme":           "VARCHAR(32) NOT NULL DEFAULT 'dark'",
            "tokens_valid_from": "DATETIME",
            "active_ips":      "TEXT",
        },
        "audit_logs": {
            "undo_commands":   "TEXT",
            "undo_label":      "VARCHAR(255)",
            "switch_id":       "INTEGER",
            "event_type":      "VARCHAR(32)",
            "ip_address":      "VARCHAR(64)",
        },
        "templates": {
            "acl_kind":        "VARCHAR(16) DEFAULT 'extended'",
        },
        "switch_health": {
            "vpc_binding_mismatch_count": "INTEGER",
        },
        "app_settings": {
            "log_auto_delete_days":   "INTEGER NOT NULL DEFAULT 0",
            "log_auto_delete_zip":    "BOOLEAN NOT NULL DEFAULT 0",
            "log_retention_last_run": "DATETIME",
        },
        "site_labels": {
            "hidden": "BOOLEAN NOT NULL DEFAULT 0",
        },
    }
    with engine.begin() as conn:
        for table, cols in wanted.items():
            try:
                existing = {r[1] for r in conn.execute(text(f"PRAGMA table_info({table})"))}
            except Exception:
                continue
            for col, ddl in cols.items():
                if col not in existing:
                    try:
                        conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
                        _column_was_added[f"{table}.{col}"] = True
                        print(f"[MIGRATE] Added {table}.{col}")
                    except Exception as e:
                        print(f"[MIGRATE] Could not add {table}.{col}: {e}")

        # The dashboard groups logs by switch and by event; neither column was
        # indexed while logs were only ever listed newest-first.
        for name, ddl in (
            ("ix_audit_logs_switch_id",
             "CREATE INDEX IF NOT EXISTS ix_audit_logs_switch_id "
             "ON audit_logs (switch_id)"),
            ("ix_audit_logs_event_type",
             "CREATE INDEX IF NOT EXISTS ix_audit_logs_event_type "
             "ON audit_logs (event_type)"),
        ):
            try:
                conn.execute(text(ddl))
            except Exception as e:
                print(f"[MIGRATE] Could not create {name}: {e}")

        _backfill_event_types(conn)
        _seed_existing_mega_visibility(conn, wanted)
        _remap_retired_themes(conn)


# Schemes that were offered and then replaced. An account still holding one
# would otherwise fall back to the default and read as though its choice had
# been forgotten, so each is remapped to its nearest successor instead.
# Old theme ids, and where an account sitting on one should land. "sepia" is
# a rename rather than a removal -- same palette, new name -- so it maps to
# the theme that replaced it and nobody's colours move.
RETIRED_THEMES = {"nocturne": "glacier", "contrast": "carbon",
                  "ember": "glacier", "nord": "slate",
                  "sepia": "evermore", "evermorr": "evermore",
                  # Withdrawn after a trial. Glacier is the nearest light
                  # scheme, so nobody who chose it lands somewhere jarring.
                  "liquid": "glacier"}


def _remap_retired_themes(conn):
    from sqlalchemy import text
    for old, new in RETIRED_THEMES.items():
        try:
            result = conn.execute(
                text("UPDATE users SET theme = :new WHERE theme = :old"),
                {"new": new, "old": old})
            if result.rowcount:
                print(f"[MIGRATE] Moved {result.rowcount} account(s) from "
                      f"the {old} theme to {new}")
        except Exception as e:
            print(f"[MIGRATE] Could not remap the {old} theme: {e}")


def _seed_existing_mega_visibility(conn, wanted):
    """
    New accounts get the mascot hidden, but accounts that predate the setting
    were already seeing it — turning it off for everyone would read as a
    regression rather than a default. Runs once, on the migration that adds
    the column.
    """
    from sqlalchemy import text
    if not _column_was_added.get("users.mega_visible"):
        return
    try:
        conn.execute(text("UPDATE users SET mega_visible = 1"))
        print("[MIGRATE] Kept the Mega visible for existing accounts")
    except Exception as e:
        print(f"[MIGRATE] Could not seed mega_visible: {e}")


def _backfill_event_types(conn):
    """
    Classify audit rows written before event_type existed.

    Only rows with no event_type are touched, so this is a no-op after the
    first run and never overwrites a value a write path recorded itself.
    History is approximate — matching on message prefixes is exactly the
    fragility the column exists to remove — but it beats an empty dashboard.
    """
    from sqlalchemy import text
    try:
        pending = conn.execute(text(
            "SELECT COUNT(*) FROM audit_logs WHERE event_type IS NULL")).scalar()
    except Exception:
        return  # Column missing on a very old file; the ALTER above reports it.
    if not pending:
        return

    updated = 0
    for event_type, prefixes in LEGACY_EVENT_PREFIXES:
        for prefix in prefixes:
            try:
                result = conn.execute(
                    text("UPDATE audit_logs SET event_type = :et "
                         "WHERE event_type IS NULL AND message LIKE :p"),
                    {"et": event_type, "p": f"{prefix}%"})
                updated += result.rowcount or 0
            except Exception as e:
                print(f"[MIGRATE] Could not classify '{prefix}': {e}")
    if updated:
        print(f"[MIGRATE] Classified {updated} of {pending} older audit entries")
