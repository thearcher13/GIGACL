"""
GIGACL — FastAPI application.

Routes are registered directly on `app` (FastAPI 0.140's include_router has a
lazy-resolution bug that silently drops routes when a router carries a prefix).
"""
import os
import re
import io
import json
import math
import ipaddress
import logging
import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse

from fastapi import (FastAPI, Depends, HTTPException, Request, WebSocket,
                     WebSocketDisconnect)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from starlette.middleware.base import BaseHTTPMiddleware
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from database import (init_db, SessionLocal, get_db, Switch, User,
                      AuditLog, SiteLabel, Template, TemplateShare,
                      SwitchHealth,
                      BUILTIN_SITES, ALL_TYPES, ALL_ROLES, ADMIN_ROLES,
                      ROLE_USER, ROLE_ADMIN, ROLE_SUPER_ADMIN, TYPE_NEXUS,
                      ACCESS_READ, ACCESS_WRITE, ALL_ACCESS,
                      WRITE_EVENT_TYPES, HEALTH_OK, HEALTH_ERROR,
                      HEALTH_NO_CREDENTIALS, TCAM_UNSUPPORTED,
                      AccessRequest, REQUEST_PENDING, REQUEST_GRANTED,
                      REQUEST_REJECTED, REQUEST_CANCELLED,
                      get_app_settings)
import database as db_models
import site_service as sites
from auth import (authenticate_user, create_access_token, get_password_hash,
                  get_current_user, require_admin, require_super_admin, get_user, verify_password,
                  validate_password, ensure_admin_exists, revoke_tokens,
                  uses_default_admin_password, settings,
                  active_ips_since, clear_active_ips, get_current_user_passive)
from switch_utils import encrypt_password, get_switch_and_password
import lockout
import schemas as sch
import switch_service as svc
import acl_service as acls
import ssh_manager
import acl_parser
import acl_report
import rule_generator
import audit
import log_retention
import request_context
import crypto
import health_collector
import terminal_service
from validators import (ValidationError, validate_ip, validate_ip_or_network,
                        validate_identifier, validate_protocol,
                        validate_port_spec, validate_sequence,
                        validate_switch_type, validate_time,
                        validate_cisco_date, validate_days,
                        validate_acl_rule_line, validate_permit_rule_line, validate_remark,
                        validate_vlan_interface, check_cli_safe,
                        validate_object_group_name, validate_prefix,
                        validate_object_group_ip, validate_port_only,
                        validate_protocol_only, validate_object_group_member_line,
                        validate_ios_port_spec, validate_icmp_type,
                        validate_established, validate_idle_timeout_minutes,
                        validate_log_delete_days, validate_log_auto_delete_days)

log = logging.getLogger("giga")

app = FastAPI(title="GIGACL", version="3.6.0")

# Same-origin only: the UI is served by this app, so nothing legitimate
# needs cross-origin access. Set GIGACL_CORS_ORIGINS to a comma-separated
# list if the frontend is ever hosted separately.
_cors_origins = [o.strip() for o in
                 os.environ.get("GIGACL_CORS_ORIGINS", "").split(",") if o.strip()]
app.add_middleware(CORSMiddleware, allow_origins=_cors_origins,
                   allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        resp = await call_next(request)
        if request.url.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

app.add_middleware(SecurityHeadersMiddleware)


class ClientIPMiddleware(BaseHTTPMiddleware):
    """Park the caller's address where audit and presence code can find it.

    `request.client.host` is the address of whatever connected to us. Behind a
    reverse proxy that is the proxy, not the user — deliberately not read from
    X-Forwarded-For, which any client can set. The trusted-hosts check on
    sign-in already trusts exactly this value, so recording anything else would
    log one address and enforce on another.
    """
    async def dispatch(self, request, call_next):
        token = request_context.set_client_ip(
            request.client.host if request.client else None)
        try:
            return await call_next(request)
        finally:
            request_context.reset_client_ip(token)

app.add_middleware(ClientIPMiddleware)


@app.exception_handler(ValidationError)
async def _validation_handler(request: Request, exc: ValidationError):
    return JSONResponse(status_code=400, content={"detail": str(exc)})


@app.exception_handler(svc.ReadOnlyAccessError)
async def _read_only_handler(request: Request, exc: svc.ReadOnlyAccessError):
    """A write attempted on a read-only switch is a permission problem, not a
    switch fault, so it must not surface as a 502 'switch error'."""
    return JSONResponse(status_code=403, content={"detail": str(exc)})


_FIELD_LABELS = {
    "switch_ids": "Switch selection", "src_ip": "Source", "dst_ip": "Destination",
    "ip_address": "IP address", "acl_name": "ACL name", "protocol": "Protocol",
    "port": "Port", "username": "Username", "password": "Password",
    "new_password": "New password", "current_password": "Current password",
    "name": "Name", "entries": "Entries", "rule_syntax": "Rule",
    "time_range": "Time range",
    "remark": "Remark",
    "remark_sequence": "Remark sequence",
    "remark_sequence_number": "Remark sequence",
    "commands": "Commands", "sequence_number": "Sequence number",
    "role": "Role", "site": "Location", "switch_type": "Switch type",
}


@app.exception_handler(RequestValidationError)
async def _pydantic_handler(request: Request, exc: RequestValidationError):
    """Turn Pydantic's raw errors into a single readable sentence."""
    parts = []
    for err in exc.errors():
        loc = [str(x) for x in err.get("loc", []) if x != "body"]
        field = loc[-1] if loc else "input"
        label = _FIELD_LABELS.get(field, field.replace("_", " ").capitalize())
        etype = err.get("type", "")
        if etype == "too_short":
            if field == "switch_ids":
                parts.append("Select at least one switch.")
            else:
                parts.append(f"{label} must contain at least one item.")
        elif etype == "missing":
            parts.append(f"{label} is required.")
        elif "string_too_long" in etype:
            parts.append(f"{label} is too long.")
        elif etype.startswith("int_"):
            parts.append(f"{label} must be a whole number.")
        elif etype.startswith("string_"):
            parts.append(f"{label} must be text.")
        else:
            parts.append(f"{label}: {err.get('msg', 'is not valid')}.")
    seen, unique = set(), []
    for p in parts:
        if p not in seen:
            seen.add(p); unique.append(p)
    return JSONResponse(status_code=400, content={"detail": " ".join(unique)})


@app.exception_handler(ssh_manager.SSHError)
async def _ssh_handler(request: Request, exc: ssh_manager.SSHError):
    return JSONResponse(status_code=502,
                        content={"detail": str(exc), "kind": "switch"})


# ═══════════════════════ META ═══════════════════════

@app.get("/api/meta")
async def meta(cu: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    """Option lists used by the UI, including this user's custom locations."""
    try:
        switch_layout = json.loads(cu.switch_layout or "{}")
        if not isinstance(switch_layout, dict):
            switch_layout = {}
    except (TypeError, ValueError):
        switch_layout = {}
    app_settings = get_app_settings(db)
    return {"sites": sites.all_labels(db, cu.username),
            "builtin_sites": list(BUILTIN_SITES),
            "custom_sites": [s for s in sites.custom_labels(db, cu.username)
                             if s not in BUILTIN_SITES],
            "switch_layout": {
                "labels": switch_layout.get("labels", []),
                "switch_ids": switch_layout.get("switch_ids", []),
            },
            "switch_types": list(ALL_TYPES),
            "roles": list(ALL_ROLES),
            "idle_timeout_minutes": app_settings.idle_timeout_minutes,
            "log_auto_delete_days": app_settings.log_auto_delete_days,
            "log_auto_delete_zip": app_settings.log_auto_delete_zip,
            "log_retention_last_run": app_settings.log_retention_last_run.isoformat()
                if app_settings.log_retention_last_run else None}


@app.post("/api/sites")
async def add_site(data: sch.SiteAdd, cu: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    name = sites.add_label(db, cu.username, data.name)
    audit.log_info(db, cu.username, f"Added location '{name}'",
                   "Custom location label created.")
    return {"message": f"Location '{name}' added.", "name": name,
            "sites": sites.all_labels(db, cu.username)}


@app.delete("/api/sites/{name}")
async def remove_site(name: str, cu: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    freed = sites.delete_label(db, cu.username, name)
    audit.log_warn(db, cu.username, f"Deleted location '{name}'",
                   f"{freed} switch(es) were set to unassigned.")
    msg = f"Location '{name}' deleted."
    if freed:
        msg += (f" {freed} switch{'es' if freed != 1 else ''} "
                f"{'were' if freed != 1 else 'was'} set to unassigned.")
    return {"message": msg, "sites": sites.all_labels(db, cu.username)}


# ═══════════════════════ AUTH ═══════════════════════

@app.post("/api/auth/token", response_model=sch.Token)
async def login(request: Request, form: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db)):
    uname = (form.username or "").strip()
    existing = get_user(db, uname)

    # Get client IP address
    client_ip = request.client.host if request.client else None

    # Reject early if the account is currently locked
    if existing:
        locked, secs = lockout.is_locked(existing)
        if locked:
            audit.log_warn(db, uname, "Sign-in blocked — account locked",
                           f"{lockout.describe_wait(secs)} remaining on the lock.", event_type=db_models.EV_LOGIN_FAILED)
            raise HTTPException(
                423,
                f"This account is locked after {lockout.MAX_ATTEMPTS} failed "
                f"attempts. Try again in {lockout.describe_wait(secs)}, or ask "
                f"an administrator to unlock it.")
        
        # Check trusted hosts before authentication
        if existing.trusted_hosts:
            from trusted_hosts import is_ip_allowed
            if not client_ip or not is_ip_allowed(client_ip, existing.trusted_hosts):
                audit.log_warn(db, uname, f"Sign-in blocked — untrusted host ({client_ip or 'unknown IP'})",
                               f"Login attempt from {client_ip or 'unknown'} is not in trusted hosts list: {existing.trusted_hosts}", event_type=db_models.EV_LOGIN_FAILED)
                raise HTTPException(
                    403,
                    "Access denied. Your IP address is not in the trusted hosts list for this account.")

    user = authenticate_user(db, uname, form.password)

    if not user:
        if existing:
            now_locked, used, left = lockout.register_failure(db, existing)
            if now_locked:
                audit.log_error(
                    db, uname, "Account locked after repeated failures",
                    f"{lockout.MAX_ATTEMPTS} failed attempts within "
                    f"{lockout.WINDOW_MINUTES} minutes. Locked for "
                    f"{lockout.LOCK_MINUTES} minutes.")
                raise HTTPException(
                    423,
                    f"Too many failed attempts. This account is locked for "
                    f"{lockout.LOCK_MINUTES} minutes.")
            audit.log_warn(db, uname, "Failed login attempt",
                           f"Wrong password. Attempt {used} of "
                           f"{lockout.MAX_ATTEMPTS}; {left} remaining before "
                           f"the account is locked.", event_type=db_models.EV_LOGIN_FAILED)
            raise HTTPException(
                401,
                f"Incorrect username or password. {left} attempt"
                f"{'s' if left != 1 else ''} remaining before the account "
                f"is locked.",
                headers={"WWW-Authenticate": "Bearer"})

        # Unknown username — do not reveal that it does not exist
        audit.log_warn(db, uname or "unknown", "Failed login attempt",
                       "No such username.", event_type=db_models.EV_LOGIN_FAILED)
        raise HTTPException(401, "Incorrect username or password.",
                            headers={"WWW-Authenticate": "Bearer"})

    # Success — clear any partial failure state
    if user.failed_attempts or user.locked_until:
        lockout.clear(db, user)

    token = create_access_token(
        {"sub": user.username},
        timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    audit.log_success(db, user.username, "Signed in",
                      f"Role: {user.role} · IP: {client_ip or 'unknown'}",
                      event_type=db_models.EV_LOGIN)
    return sch.Token(access_token=token, token_type="bearer",
                     role=user.role, username=user.username,
                     mega=user.mega or "byte",
                     mega_visible=bool(user.mega_visible),
                     theme=user.theme or DEFAULT_THEME)


@app.get("/api/auth/me")
async def me(cu: User = Depends(get_current_user)):
    return {"username": cu.username, "role": cu.role,
            "mega": cu.mega or "byte",
            "mega_visible": bool(cu.mega_visible),
            "theme": cu.theme or DEFAULT_THEME}


@app.get("/api/auth/session")
async def session_check(cu: User = Depends(get_current_user_passive)):
    """Is this token still good?

    The app polls this so that an account which was deleted, renamed or had its
    authority revoked stops sitting on a signed-in page until its owner happens
    to click something. Any of those makes the dependency raise 401, which the
    client already treats as "sign in again". Deliberately passive: polling is
    not the user doing anything, so it must not mark them present.
    """
    return {"username": cu.username, "role": cu.role}


@app.post("/api/auth/logout")
async def logout(cu: User = Depends(get_current_user),
                 db: Session = Depends(get_db)):
    """
    Clear the presence marker so the signer-out stops counting as active.

    Signing out is otherwise entirely client-side, so without this the account
    kept showing on the dashboard until its last_seen aged past the idle
    window. This does not revoke the token — there is no revocation list — so
    a request made with it afterwards will mark the account active again,
    which is the honest answer.
    """
    cu.last_seen = None
    clear_active_ips(cu)
    db.commit()
    audit.log_info(db, cu.username, "Signed out", "",
                   event_type=db_models.EV_LOGIN)
    return {"message": "Signed out."}


ROLE_RANK = {ROLE_USER: 1, ROLE_ADMIN: 2, ROLE_SUPER_ADMIN: 3}
MEGA_TYPES = ("byte", "spark", "orbit", "moss")

# Colour schemes. 'dark' and 'light' keep the ids they have always had, so a
# browser carrying one in localStorage migrates into users.theme without the
# person's colours moving; the display names live in the frontend.
THEMES = ("dark", "light", "slate", "glacier", "evermore", "carbon")
DEFAULT_THEME = "dark"


def _can_manage(actor: User, target: User) -> bool:
    """
    An administrator may act on a target with the same or lower privilege.
    Super admins may act on anyone (including other super admins).
    """
    return ROLE_RANK.get(actor.role, 0) >= ROLE_RANK.get(target.role, 0)


@app.get("/api/auth/users", response_model=List[sch.UserResponse])
async def list_users(cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    rows = db.query(User).order_by(User.username).all()
    out = []
    for u in rows:
        st = lockout.lock_state(u)
        out.append(sch.UserResponse(
            id=u.id, username=u.username, role=u.role,
            locked=st["locked"], locked_until=st["locked_until"],
            seconds_remaining=st["seconds_remaining"],
            failed_attempts=st["failed_attempts"],
            trusted_hosts=u.trusted_hosts,
            mega=u.mega or "byte"))
    return out


@app.post("/api/auth/users/{user_id}/unlock")
async def unlock_user(user_id: int, cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    """Clear a lockout. Requires equal or higher privilege than the target."""
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    if not _can_manage(cu, u):
        raise HTTPException(
            403,
            f"You need the same or higher privilege than '{u.username}' "
            f"to unlock that account.")

    locked, _ = lockout.is_locked(u)
    had_failures = bool(u.failed_attempts)
    if not locked and not had_failures:
        return {"message": f"'{u.username}' is not locked.", "changed": False}

    lockout.clear(db, u)
    audit.log_success(db, cu.username, f"Unlocked account '{u.username}'",
                      "Failed-attempt counter and lock were cleared.")
    return {"message": f"'{u.username}' has been unlocked.", "changed": True}


@app.post("/api/auth/users", response_model=sch.UserResponse)
async def create_user(data: sch.UserCreate, cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    uname = check_cli_safe((data.username or "").strip(), "Username")
    if not uname:
        raise ValidationError("Username is required.")
    if not re.fullmatch(r"[A-Za-z0-9._\-]{2,64}", uname):
        raise ValidationError(
            "Username must be 2–64 characters using letters, digits, "
            "dot, dash or underscore.")
    if get_user(db, uname):
        raise ValidationError(f"A user named '{uname}' already exists.")
    if data.role not in ALL_ROLES:
        raise ValidationError("Choose a valid role.")
    if data.role == ROLE_SUPER_ADMIN and cu.role != ROLE_SUPER_ADMIN:
        raise HTTPException(403, "Only a super admin can create a super admin.")
    err = validate_password(data.password)
    if err:
        raise ValidationError(err)

    u = User(username=uname, hashed_password=get_password_hash(data.password),
             role=data.role)
    db.add(u); db.commit(); db.refresh(u)
    audit.log_success(db, cu.username, f"Created user '{uname}'",
                      f"Role assigned: {data.role}")
    return u


@app.put("/api/auth/users/{user_id}/role")
async def update_role(user_id: int, data: sch.RoleUpdate,
                      cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    if data.role not in ALL_ROLES:
        raise ValidationError("Choose a valid role.")
    if u.id == cu.id:
        raise HTTPException(400, "You cannot change your own role.")
    if not _can_manage(cu, u):
        raise HTTPException(403, "Only a super admin can modify a super admin.")
    if data.role == ROLE_SUPER_ADMIN and cu.role != ROLE_SUPER_ADMIN:
        raise HTTPException(403, "Only a super admin can grant super admin.")
    if u.role == data.role:
        return {"message": f"'{u.username}' is already {data.role}.",
                "changed": False}
    # Refuse while they are still signed in. A role change rewrites what the
    # whole UI offers -- which pages exist, whether the Requests section is
    # theirs at all -- and a session that started under the old role carries
    # stale state until it ends. Revoking their token underneath them would
    # do it silently mid-task; this makes the handover explicit instead.
    cutoff = _presence_cutoff(db)
    if u.last_seen and u.last_seen >= cutoff:
        raise HTTPException(
            409, f"'{u.username}' is still signed in. Ask them to sign out, "
                 "then change the role — their session was created under the "
                 "old role and would keep it until they do.")
    old = u.role
    u.role = data.role
    # Templates are an admin feature and can only ever be shared with admins,
    # so a demotion has to take the shares with it. Left behind, the template
    # goes on listing somebody who can no longer open the page.
    dropped = 0
    if data.role == ROLE_USER:
        dropped = db.query(TemplateShare).filter(
            TemplateShare.username == u.username).delete(synchronize_session=False)
    db.commit()
    revoke_tokens(db, u)
    audit.log_success(db, cu.username, f"Changed role of '{u.username}'",
                      f"{old} → {data.role}"
                      + (f"\nRemoved {dropped} template share(s) they can no longer use."
                         if dropped else ""))
    return {"message": f"'{u.username}' is now {data.role}.", "changed": True}


@app.put("/api/auth/users/{user_id}/username")
async def update_username(user_id: int, data: sch.UsernameUpdate,
                          cu: User = Depends(require_super_admin),
                          db: Session = Depends(get_db)):
    """Rename an account and migrate all username-keyed ownership records."""
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    if u.id != cu.id and u.role == ROLE_SUPER_ADMIN:
        raise HTTPException(
            403, "Only a super admin can edit their own username. "
                 "Another super admin's username can't be changed for them.")

    uname = check_cli_safe((data.username or "").strip(), "Username")
    if not re.fullmatch(r"[A-Za-z0-9._\-]{2,64}", uname):
        raise ValidationError(
            "Username must be 2–64 characters using letters, digits, "
            "dot, dash or underscore.")
    if uname == u.username:
        return {"message": f"The username is already '{uname}'.",
                "changed": False, "username": uname}
    collision = next((other for other in db.query(User).all()
                      if other.id != u.id and
                      other.username.lower() == uname.lower()), None)
    if collision:
        raise ValidationError(f"A user named '{uname}' already exists.")

    old = u.username
    switch_count = db.query(Switch).filter(
        Switch.owner_username == old).update(
            {"owner_username": uname}, synchronize_session=False)
    site_count = db.query(SiteLabel).filter(
        SiteLabel.owner_username == old).update(
            {"owner_username": uname}, synchronize_session=False)
    db.query(Template).filter(Template.owner_username == old).update(
        {"owner_username": uname}, synchronize_session=False)
    db.query(TemplateShare).filter(TemplateShare.username == old).update(
        {"username": uname}, synchronize_session=False)
    db.query(AuditLog).filter(AuditLog.username == old).update(
        {"username": uname}, synchronize_session=False)
    u.username = uname
    db.commit()

    audit.log_success(
        db, cu.username, f"Renamed user '{old}' to '{uname}'",
        f"Migrated ownership of {switch_count} switch(es) and "
        f"{site_count} custom location(s). Switch SSH usernames were unchanged.")
    result = {"message": f"User '{old}' was renamed to '{uname}'.",
              "changed": True, "username": uname}
    if u.id == cu.id:
        # The signed-in token's subject is now stale — issue a fresh one so
        # the caller's session continues without forcing a re-login.
        result["token"] = create_access_token(
            {"sub": uname},
            timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES))
    return result


@app.delete("/api/auth/users/{user_id}")
async def delete_user(user_id: int, cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    if u.id == cu.id:
        raise HTTPException(400, "You cannot delete your own account.")
    if not _can_manage(cu, u):
        raise HTTPException(403, "Only a super admin can delete a super admin.")
    uname, urole = u.username, u.role

    # Remove everything owned by this account: switches (with their stored
    # credentials), any VPC references to them, and their custom locations.
    owned = db.query(Switch).filter(Switch.owner_username == uname).all()
    owned_ids = [s.id for s in owned]
    for s in owned:
        ssh_manager.invalidate_session(uname, s.ip_address)
    if owned_ids:
        db.query(Switch).filter(Switch.vpc_peer_id.in_(owned_ids))\
                        .update({"vpc_peer_id": None}, synchronize_session=False)
    sw_count = db.query(Switch).filter(Switch.owner_username == uname)\
                               .delete(synchronize_session=False)
    site_count = db.query(SiteLabel).filter(SiteLabel.owner_username == uname)\
                                    .delete(synchronize_session=False)
    owned_template_ids = [t.id for t in
                          db.query(Template).filter(Template.owner_username == uname).all()]
    if owned_template_ids:
        db.query(TemplateShare).filter(
            TemplateShare.template_id.in_(owned_template_ids)).delete(synchronize_session=False)
    db.query(Template).filter(Template.owner_username == uname)\
                      .delete(synchronize_session=False)
    db.query(TemplateShare).filter(TemplateShare.username == uname)\
                           .delete(synchronize_session=False)
    db.delete(u)
    db.commit()

    detail = (f"The deleted account had the role: {urole}. "
              f"Removed {sw_count} switch inventory entr"
              f"{'y' if sw_count == 1 else 'ies'} "
              f"and {site_count} custom location"
              f"{'' if site_count == 1 else 's'}.")
    audit.log_warn(db, cu.username, f"Deleted user '{uname}'", detail)

    msg = f"User '{uname}' was deleted."
    if sw_count:
        msg += (f" Their {sw_count} switch"
                f"{'' if sw_count == 1 else 'es'} "
                f"and saved credentials were also removed.")
    return {"message": msg, "switches_removed": sw_count}


@app.put("/api/auth/me/password")
async def change_password(data: sch.PasswordChange,
                          cu: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    if not verify_password(data.current_password, cu.hashed_password):
        audit.log_warn(db, cu.username, "Password change rejected",
                       "The current password supplied was incorrect.")
        raise ValidationError("Your current password is incorrect.")
    if verify_password(data.new_password, cu.hashed_password):
        raise ValidationError("The new password must differ from the current one.")
    err = validate_password(data.new_password)
    if err:
        raise ValidationError(err)
    cu.hashed_password = get_password_hash(data.new_password)
    db.commit()
    # Every session opened under the old password stops working — that is the
    # point of changing it. The caller gets a fresh token so the tab they are
    # sitting in is not signed out for doing the right thing.
    revoke_tokens(db, cu)
    fresh = create_access_token({"sub": cu.username, "role": cu.role})
    audit.log_success(db, cu.username, "Changed own password",
                      "Other sessions signed out.")
    return {"message": "Your password has been updated.",
            "access_token": fresh}


@app.put("/api/auth/me/theme")
async def update_own_theme(data: sch.ThemeUpdate,
                           cu: User = Depends(get_current_user),
                           db: Session = Depends(get_db)):
    """Let every authenticated user choose their own colour scheme."""
    theme = (data.theme or "").strip().lower()
    if theme not in THEMES:
        raise ValidationError("Choose a valid theme.")
    if (cu.theme or DEFAULT_THEME) == theme:
        return {"message": "That is already your theme.",
                "theme": theme, "changed": False}
    cu.theme = theme
    db.commit()
    return {"message": "Your theme has been saved.",
            "theme": theme, "changed": True}


@app.put("/api/auth/me/mega")
async def update_own_mega(data: sch.MegaUpdate,
                          cu: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """Let every authenticated user choose their own animated mascot."""
    mega = (data.mega or "").strip().lower()
    if mega not in MEGA_TYPES:
        raise ValidationError("Choose a valid Mega.")
    if (cu.mega or "byte") == mega:
        return {"message": f"{mega.title()} is already your Mega.",
                "mega": mega, "changed": False}
    cu.mega = mega
    db.commit()
    return {"message": f"Your Mega is now {mega.title()}.",
            "mega": mega, "changed": True}


@app.put("/api/auth/me/mega-visible")
async def update_own_mega_visible(data: sch.MegaVisibleUpdate,
                                  cu: User = Depends(get_current_user),
                                  db: Session = Depends(get_db)):
    """
    Remember whether the mascot is shown, per account rather than per browser.

    It starts hidden for a new account, and localStorage alone could not tell
    a new user apart from an existing one on an unfamiliar machine.
    """
    cu.mega_visible = bool(data.visible)
    db.commit()
    return {"visible": cu.mega_visible}


@app.put("/api/auth/users/{user_id}/password")
async def reset_password(user_id: int, data: sch.AdminPasswordReset,
                         cu: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    if u.role == ROLE_SUPER_ADMIN and cu.role != ROLE_SUPER_ADMIN and u.id != cu.id:
        raise HTTPException(403,
            "Only a super admin can reset another super admin's password.")
    err = validate_password(data.new_password)
    if err:
        raise ValidationError(err)
    u.hashed_password = get_password_hash(data.new_password)
    db.commit()
    revoke_tokens(db, u)
    audit.log_success(db, cu.username, f"Reset password for '{u.username}'", "")
    return {"message": f"Password for '{u.username}' has been reset."}


@app.put("/api/auth/me/trusted-hosts")
async def update_own_trusted_hosts(data: sch.TrustedHostsUpdate,
                                    cu: User = Depends(require_admin),
                                    db: Session = Depends(get_db)):
    """Admins can update their own trusted hosts."""
    from trusted_hosts import validate_trusted_hosts_format, format_trusted_hosts_list
    
    # Validate format
    err = validate_trusted_hosts_format(data.trusted_hosts)
    if err:
        raise ValidationError(err)
    
    old_hosts = cu.trusted_hosts or "none"
    cu.trusted_hosts = data.trusted_hosts.strip() if data.trusted_hosts.strip() else None
    db.commit()
    
    new_display = ', '.join(format_trusted_hosts_list(cu.trusted_hosts)) if cu.trusted_hosts else "none"
    audit.log_info(db, cu.username, "Updated own trusted hosts",
                   f"Changed from {old_hosts} to {new_display}")
    
    return {"message": "Your trusted hosts have been updated.",
            "trusted_hosts": cu.trusted_hosts}


@app.put("/api/auth/users/{user_id}/trusted-hosts")
async def update_user_trusted_hosts(user_id: int, data: sch.TrustedHostsUpdate,
                                     cu: User = Depends(require_super_admin),
                                     db: Session = Depends(get_db)):
    """Only super admins can update trusted hosts for other users."""
    from trusted_hosts import validate_trusted_hosts_format, format_trusted_hosts_list
    
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "That user no longer exists.")
    
    # Validate format
    err = validate_trusted_hosts_format(data.trusted_hosts)
    if err:
        raise ValidationError(err)
    
    old_hosts = u.trusted_hosts or "none"
    u.trusted_hosts = data.trusted_hosts.strip() if data.trusted_hosts.strip() else None
    db.commit()
    
    new_display = ', '.join(format_trusted_hosts_list(u.trusted_hosts)) if u.trusted_hosts else "none"
    audit.log_success(db, cu.username, f"Updated trusted hosts for '{u.username}'",
                      f"Changed from {old_hosts} to {new_display}")
    
    return {"message": f"Trusted hosts for '{u.username}' have been updated.",
            "trusted_hosts": u.trusted_hosts}



# ══════════ ACCESS REQUESTS ══════════
# Somebody without write access asks an admin to open a path. The request
# carries the whole context of the check that produced it, so an admin can act
# on it without re-running anything.

def _request_out(r: AccessRequest) -> Dict[str, Any]:
    return {
        "id": r.id,
        "requester": r.requester_username,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "switch_id": r.switch_id,
        "switch_ip": r.switch_ip,
        "switch_label": r.switch_label,
        "src_ip": r.src_ip, "dst_ip": r.dst_ip,
        "protocol": r.protocol, "port": r.port, "icmp_type": r.icmp_type,
        "denied_side": r.denied_side, "vlan": r.vlan,
        "acl_name": r.acl_name, "matched_rule": r.matched_rule,
        "remark": r.remark,
        "status": r.status,
        "resolved_at": r.resolved_at.isoformat() if r.resolved_at else None,
        "resolved_by": r.resolved_by,
        "resolution_note": r.resolution_note,
    }


def _describe_request(r: AccessRequest) -> str:
    bits = f"{r.src_ip} → {r.dst_ip} {r.protocol}"
    if r.port:
        bits += f"/{r.port}"
    if r.icmp_type:
        bits += f" type {r.icmp_type}"
    return f"{bits} on {r.switch_label or r.switch_ip or 'a switch'}"


def _can_write_switch(sw: Optional[Switch], cu: User) -> bool:
    """Whether this account could make the change itself."""
    if sw is None:
        return False
    if cu.role == ROLE_USER:
        return False
    return _effective_access(sw, cu.role) != ACCESS_READ


@app.post("/api/requests")
async def create_access_request(data: sch.AccessRequestCreate,
                                cu: User = Depends(get_current_user),
                                db: Session = Depends(get_db)):
    """
    Raise a request for access the caller cannot grant themselves.

    Refused for anyone who could simply make the change: a write grant means
    the Add ACL Rule page is right there, and a request would be a slower way
    of doing the same thing.
    """
    src = validate_ip_or_network(data.src_ip, "Source", allow_group=False)
    dst = validate_ip_or_network(data.dst_ip, "Destination", allow_group=False)
    proto = validate_protocol(data.protocol)
    port = validate_port_spec(data.port, proto)
    icmp_type = validate_icmp_type(data.icmp_type, proto)

    visible = {x.id: x for x in _visible_switches(cu, db)}
    sw = visible.get(data.switch_id)
    if not sw:
        raise HTTPException(404, "That switch is not one of yours.")
    if _can_write_switch(sw, cu):
        raise HTTPException(
            400, f"You already have write access to {sw.hostname or sw.ip_address}. "
                 "Add the rule directly instead of requesting it.")

    targets = [sw]
    if data.include_peer and sw.vpc_peer_id:
        peer = visible.get(sw.vpc_peer_id)
        # Each peer gets its own row: they are approved and applied one at a
        # time, so one request covering both could only ever be half-done.
        if peer and not _can_write_switch(peer, cu):
            targets.append(peer)

    made = []
    for target in targets:
        r = AccessRequest(
            requester_username=cu.username,
            switch_id=target.id,
            switch_ip=target.ip_address,
            switch_label=target.hostname or target.ip_address,
            src_ip=src, dst_ip=dst,
            protocol=proto, port=port, icmp_type=icmp_type,
            denied_side=data.denied_side, vlan=data.vlan,
            acl_name=data.acl_name, matched_rule=data.matched_rule,
            remark=(data.remark or None),
            status=REQUEST_PENDING,
        )
        db.add(r)
        db.flush()
        made.append(r)
        audit.log_info(db, cu.username, f"Requested access: {_describe_request(r)}",
                       (r.remark or ""), switch_id=target.id)
    db.commit()
    return {"message": f"{len(made)} access request(s) sent to the administrators.",
            "requests": [_request_out(r) for r in made]}


@app.get("/api/requests/mine")
async def my_access_requests(cu: User = Depends(get_current_user),
                             db: Session = Depends(get_db)):
    """
    The caller's own requests, and how many have been answered since they last
    looked -- which is what raises the toast on the next load.
    """
    rows = db.query(AccessRequest)\
             .filter(AccessRequest.requester_username == cu.username)\
             .order_by(AccessRequest.created_at.desc()).all()
    unseen = [r for r in rows
              if r.status in (REQUEST_GRANTED, REQUEST_REJECTED)
              and not r.seen_by_requester]
    return {"requests": [_request_out(r) for r in rows],
            "unseen": len(unseen),
            "unseen_granted": len([r for r in unseen if r.status == REQUEST_GRANTED]),
            "unseen_rejected": len([r for r in unseen if r.status == REQUEST_REJECTED])}


@app.post("/api/requests/mine/seen")
async def mark_requests_seen(cu: User = Depends(get_current_user),
                             db: Session = Depends(get_db)):
    rows = db.query(AccessRequest)\
             .filter(AccessRequest.requester_username == cu.username,
                     AccessRequest.seen_by_requester == False).all()  # noqa: E712
    for r in rows:
        r.seen_by_requester = True
    db.commit()
    return {"message": "Marked as seen.", "cleared": len(rows)}


@app.put("/api/requests/{request_id}")
async def edit_access_request(request_id: int, data: sch.AccessRequestRemark,
                              cu: User = Depends(get_current_user),
                              db: Session = Depends(get_db)):
    """Only the remark, and only while nobody has acted on it."""
    r = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not r or r.requester_username != cu.username:
        raise HTTPException(404, "That request no longer exists.")
    if r.status != REQUEST_PENDING:
        raise HTTPException(400, "That request has already been answered.")
    r.remark = (data.remark or "").strip() or None
    db.commit()
    return {"message": "Request updated.", "request": _request_out(r)}


@app.delete("/api/requests/{request_id}")
async def cancel_access_request(request_id: int,
                                cu: User = Depends(get_current_user),
                                db: Session = Depends(get_db)):
    r = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not r or r.requester_username != cu.username:
        raise HTTPException(404, "That request no longer exists.")
    if r.status != REQUEST_PENDING:
        raise HTTPException(400, "That request has already been answered.")
    r.status = REQUEST_CANCELLED
    r.resolved_at = datetime.utcnow()
    r.resolved_by = cu.username
    r.seen_by_requester = True
    audit.log_info(db, cu.username, f"Cancelled their access request: {_describe_request(r)}",
                   "", switch_id=r.switch_id)
    db.commit()
    return {"message": "Request cancelled."}


@app.get("/api/requests")
async def list_access_requests(cu: User = Depends(require_admin),
                               db: Session = Depends(get_db)):
    """
    The pending requests this admin is expected to deal with.

    Scoped to the switches they actually hold, because a request they cannot
    act on is somebody else's job and only clutters the queue. A super admin
    sees all of them, since only they can see the whole inventory and so only
    they can tell that a request has nobody to answer it.

    Your own requests are never listed: you raised them precisely because you
    could not action them, and answering your own would defeat the point.
    """
    rows = db.query(AccessRequest)\
             .filter(AccessRequest.status == REQUEST_PENDING,
                     AccessRequest.requester_username != cu.username)\
             .order_by(AccessRequest.created_at.desc()).all()
    out = []
    for r in rows:
        mine = db.query(Switch).filter(Switch.ip_address == r.switch_ip,
                                       Switch.owner_username == cu.username).first()
        # Only people who could actually action it, plus super admins. Holding
        # the switch read-only is the same as not holding it here: you could
        # not add the rule either way, so the request is somebody else's to
        # answer and listing it only invites a dead end.
        if not _can_write_switch(mine, cu) and cu.role != ROLE_SUPER_ADMIN:
            continue
        item = _request_out(r)
        # The switch the *acting admin* would apply this to, which is their own
        # entry for that device, not the requester's.
        item["my_switch_id"] = mine.id if mine else None
        item["can_apply"] = bool(mine and _can_write_switch(mine, cu))
        item["reason_blocked"] = (
            None if item["can_apply"]
            else "This switch is not in your inventory." if not mine
            else f"You have read-only access to {mine.hostname or mine.ip_address}.")
        out.append(item)
    return {"requests": out}


def _resolve_request(db: Session, r: AccessRequest, cu: User,
                     status: str, note: Optional[str]) -> None:
    r.status = status
    r.resolved_at = datetime.utcnow()
    r.resolved_by = cu.username
    r.resolution_note = (note or "").strip() or None
    # Cleared so the requester gets told on their next load.
    r.seen_by_requester = False


@app.post("/api/requests/{request_id}/done")
async def complete_access_request(request_id: int, data: sch.AccessRequestResolve,
                                  cu: User = Depends(require_admin),
                                  db: Session = Depends(get_db)):
    """Mark it granted. Removes it from every admin's list."""
    r = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not r:
        raise HTTPException(404, "That request no longer exists.")
    if r.status != REQUEST_PENDING:
        raise HTTPException(400, f"That request is already {r.status}.")
    _resolve_request(db, r, cu, REQUEST_GRANTED, data.note)
    # Deliberately "marked done" rather than "granted": the app cannot see
    # whether the rule was actually added, only that an admin says they are
    # finished with it. Claiming more than that in the audit trail would be
    # inventing a fact.
    audit.log_success(
        db, cu.username, f"Marked done an access request from '{r.requester_username}'",
        f"{_describe_request(r)}" + (f"\n{r.resolution_note}" if r.resolution_note else ""),
        switch_id=r.switch_id)
    db.commit()
    return {"message": f"Marked done. '{r.requester_username}' will be told."}


@app.post("/api/requests/{request_id}/dismiss")
async def dismiss_access_request(request_id: int, data: sch.AccessRequestResolve,
                                 cu: User = Depends(require_admin),
                                 db: Session = Depends(get_db)):
    """Turn it down. Removes it from every admin's list."""
    r = db.query(AccessRequest).filter(AccessRequest.id == request_id).first()
    if not r:
        raise HTTPException(404, "That request no longer exists.")
    if r.status != REQUEST_PENDING:
        raise HTTPException(400, f"That request is already {r.status}.")
    _resolve_request(db, r, cu, REQUEST_REJECTED, data.note)
    audit.log_warn(
        db, cu.username, f"Dismissed access request from '{r.requester_username}'",
        f"{_describe_request(r)}" + (f"\nReason: {r.resolution_note}" if r.resolution_note else ""),
        switch_id=r.switch_id)
    db.commit()
    return {"message": f"Dismissed. '{r.requester_username}' will be told it was rejected."}


@app.put("/api/settings/idle-timeout")
async def update_idle_timeout(data: sch.IdleTimeoutUpdate,
                              cu: User = Depends(require_super_admin),
                              db: Session = Depends(get_db)):
    """Only super admins can change the app-wide idle-logout timeout."""
    minutes = validate_idle_timeout_minutes(data.idle_timeout_minutes)
    app_settings = get_app_settings(db)
    old = app_settings.idle_timeout_minutes
    app_settings.idle_timeout_minutes = minutes
    db.commit()

    label = "Never" if minutes == 0 else f"{minutes} minute(s)"
    old_label = "Never" if old == 0 else f"{old} minute(s)"
    audit.log_success(db, cu.username, f"Changed idle logout timeout to {label}",
                      f"Changed from {old_label} to {label}. Applies to every user.")
    return {"message": f"Idle logout timeout set to {label}.",
            "idle_timeout_minutes": minutes}


@app.put("/api/settings/log-retention")
async def update_log_retention(data: sch.LogRetentionUpdate,
                               cu: User = Depends(require_super_admin),
                               db: Session = Depends(get_db)):
    """Only super admins can change the scheduled audit-log auto-delete."""
    days = validate_log_auto_delete_days(data.auto_delete_days)
    app_settings = get_app_settings(db)
    old = app_settings.log_auto_delete_days
    app_settings.log_auto_delete_days = days
    app_settings.log_auto_delete_zip = bool(data.auto_delete_zip)
    db.commit()

    label = "Never" if days == 0 else f"{days} day(s)"
    old_label = "Never" if old == 0 else f"{old} day(s)"
    audit.log_success(db, cu.username, f"Changed audit log auto-delete to {label}",
                      f"Changed from {old_label} to {label}. "
                      f"Zip backup: {'on' if data.auto_delete_zip else 'off'}.")
    return {"message": f"Auto-delete set to {label}.",
            "auto_delete_days": days, "auto_delete_zip": app_settings.log_auto_delete_zip}


# ═══════════════════════ LOGS ═══════════════════════

@app.get("/api/logs", response_model=List[sch.LogResponse])
async def logs(limit: int = 400, cu: User = Depends(get_current_user),
               db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if cu.role != ROLE_SUPER_ADMIN:
        q = q.filter(AuditLog.username == cu.username)
    limit = max(1, min(limit, 2000))
    rows = q.order_by(AuditLog.timestamp.desc()).limit(limit).all()
    # Logs can reference other users' switches (superadmins see everyone's
    # logs); look up each switch's location/label independent of ownership.
    switches = db.query(Switch.id, Switch.site, Switch.hostname,
                        Switch.ip_address).all()
    site_by_switch = {sid: site for sid, site, _h, _ip in switches}
    label_by_switch = {sid: (hostname or ip) for sid, _s, hostname, ip in switches}
    return [
        sch.LogResponse(
            id=r.id, timestamp=r.timestamp, level=r.level, username=r.username,
            message=r.message, description=r.description,
            undo_commands=r.undo_commands, undo_label=r.undo_label,
            switch_id=r.switch_id,
            ip_address=r.ip_address,
            switch_site=site_by_switch.get(r.switch_id) if r.switch_id else None,
            switch_label=label_by_switch.get(r.switch_id) if r.switch_id else None,
        ) for r in rows
    ]


@app.post("/api/logs/delete-older-than")
async def delete_logs_older_than(data: sch.LogDeleteRequest,
                                 cu: User = Depends(require_super_admin),
                                 db: Session = Depends(get_db)):
    """Manually delete audit logs older than a chosen period (super admin
    only), optionally streaming a zip backup of what was removed."""
    days = validate_log_delete_days(data.days)
    rows = log_retention.rows_older_than(db, days)

    # Asking for a zip both downloads it and leaves a copy in the project's
    # log_backups folder, so a manual clear-out is recoverable even if the
    # download is lost.
    zip_bytes = log_retention.build_zip(rows) if data.zip and rows else None
    saved_to = log_retention.save_backup_to_disk(zip_bytes) if zip_bytes else None
    deleted = log_retention.delete_rows(db, rows)
    audit.log_success(db, cu.username, f"Deleted {deleted} old audit log(s)",
                      f"{cu.username} manually deleted entries older than "
                      f"{days} day(s). "
                      + (f"Backup downloaded and saved to {saved_to}."
                         if saved_to else "No backup was kept."))

    if zip_bytes is not None:
        stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        return StreamingResponse(
            io.BytesIO(zip_bytes), media_type="application/zip",
            headers={"Content-Disposition":
                     f'attachment; filename="audit_logs_backup_{stamp}.zip"'})
    return {"message": f"Deleted {deleted} log entries older than {days} day(s).",
            "deleted": deleted}


def _normalized_log_undo_commands(commands: Any, label: Optional[str]) -> List[str]:
    """Repair legacy time-range undo data that accidentally stored CLI errors."""
    if not isinstance(commands, list) or not all(isinstance(c, str) for c in commands):
        raise ValidationError("Invalid undo data in log entry.")
    cleaned = [command.strip() for command in commands if command.strip()]
    invalid_output = any(
        command == "^" or
        "% invalid command" in command.lower() or
        command.lower().startswith("show running-config")
        for command in cleaned
    )
    match = re.fullmatch(
        r"restore\s+time-range\s+([A-Za-z0-9_.-]+)",
        (label or "").strip(), re.IGNORECASE,
    )
    if invalid_output and match:
        # Old logs cannot recover entries that were never captured. Restoring
        # the named, empty range is the only safe and valid Cisco command.
        return [f"time-range {match.group(1)}"]
    if invalid_output:
        raise ValidationError("The stored undo data contains switch error output.")
    return cleaned


@app.post("/api/logs/undo")
async def undo_from_log(data: sch.UndoFromLogRequest, cu: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    """Execute undo commands from an audit log entry."""
    log_entry = db.query(AuditLog).filter(AuditLog.id == data.log_id).first()
    if not log_entry:
        raise HTTPException(404, "Log entry not found.")

    # Undo touches the switch the entry's author owns, so only that author may
    # run it. Switch ownership already blocks this further down, but the check
    # belongs here too: super admins can see everyone's entries.
    if log_entry.username != cu.username:
        raise HTTPException(
            403, f"Only {log_entry.username} can undo their own change.")

    if not log_entry.undo_commands:
        raise HTTPException(400, "This log entry has no undo data.")
    
    # Parse undo commands from JSON
    import json
    try:
        undo_commands = _normalized_log_undo_commands(
            json.loads(log_entry.undo_commands), log_entry.undo_label)
    except Exception:
        raise HTTPException(400, "Invalid undo data in log entry.")

    if not undo_commands:
        raise HTTPException(400, "This log entry has no valid undo commands.")
    for command in undo_commands:
        check_cli_safe(command, "Undo command")
    
    if not log_entry.switch_id:
        raise HTTPException(400, "No switch associated with this log entry.")
    
    # Get the switch
    s = db.query(Switch).filter(Switch.id == log_entry.switch_id).first()
    if not s:
        raise HTTPException(404, "Switch no longer exists.")
    
    # Get switch credentials
    sw, pw, enable_pw = get_switch_and_password(log_entry.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, undo_commands, timeout=45)
    if not ok:
        audit.log_error(db, cu.username,
                       f"Failed to undo: {log_entry.message}",
                       f"Switch: {s.hostname or s.ip_address}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {
            "success": False,
            "message": err or "The switch rejected the undo commands.",
            "output": out,
        }

    latest_save = _latest_switch_log(
        db, s.id, cu.username, "Saved configuration on ")
    post_save_undo = _log_is_newer(latest_save, log_entry)
    audit.log_success(
        db, cu.username,
        (f"Undid a saved change on {s.hostname or s.ip_address}"
         if post_save_undo else f"Undid: {log_entry.message}"),
        f"Switch: {s.hostname or s.ip_address}\nCommands: {' ; '.join(undo_commands)}",
        switch_id=s.id,
                      event_type=db_models.EV_UNDO)

    # Clear undo data from the original log entry so it can't be undone twice
    log_entry.undo_commands = None
    log_entry.undo_label = None
    db.commit()

    message = f"Change reverted on {s.hostname or s.ip_address}."
    if post_save_undo:
        message += " Running-config now has UNSAVED changes."
    return {"success": True, "message": message, "output": out}


# ═══════════════════════ BULK ADD / GRANT ═══════════════════════
#
# One endpoint serves two things that are the same operation underneath:
# adding several switches for yourself, and a super admin adding them on
# other people's behalf. The only difference is whose rows get written.

MAX_BULK_IPS = 50


def _resolve_grant_targets(data: sch.SwitchBulkAdd, cu: User,
                           db: Session) -> List[User]:
    """Who the switches are being added for, with the rules that govern it."""
    names = [n.strip() for n in (data.usernames or []) if n and n.strip()]
    if names and cu.role != ROLE_SUPER_ADMIN:
        raise HTTPException(403, "Only a super admin can add switches for other people.")

    people: List[User] = []
    seen = set()
    for name in names:
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        user = get_user(db, name)
        if user is None:
            raise ValidationError(f"There is no user called '{name}'.")
        people.append(user)

    # Adding for yourself is the default when nobody else is named.
    if data.include_self or not people:
        if cu.username.lower() not in seen:
            people.insert(0, cu)
    return people


def _access_for(user: User, requested: Optional[str]) -> str:
    """
    Resolve the privilege for one person.

    A plain user has no write features anywhere in the app, so granting them
    write access would be meaningless — it is forced to read rather than
    rejected, since the alternative is failing a bulk grant over a setting the
    grantee could never have used.
    """
    level = (requested or ACCESS_WRITE).strip().lower()
    if level not in ALL_ACCESS:
        raise ValidationError(
            f"Access must be '{ACCESS_READ}' or '{ACCESS_WRITE}'.")
    if user.role == ROLE_USER:
        return ACCESS_READ
    return level


def _terminal_for(access: str, requested: Optional[bool]) -> bool:
    """Whether a grant at this level carries an interactive terminal.

    Read-only has never included one — a terminal is unrestricted access to the
    device, which is the whole thing read-only withholds. Write carries one
    unless the granter says otherwise, so an unset request means yes and the
    setting can only ever narrow a write grant, never widen a read-only one.
    """
    if access == ACCESS_READ:
        return False
    return True if requested is None else bool(requested)


def _conflict_for(existing: Optional[Switch], holder: User, cu: User,
                  overwrite_granted: bool) -> Optional[str]:
    """
    Why this switch cannot be written for `holder`, or None if it can.

    Three cases, deliberately different:
      · another super admin's own switch — never touched
      · a switch the holder added themselves — theirs, so refused
      · a switch another super admin granted — taken over, but only on confirm
    """
    if existing is None:
        return None
    if holder.username == cu.username:
        return None                       # your own row: an ordinary update
    if not existing.created_by:
        if holder.role == ROLE_SUPER_ADMIN:
            return (f"{holder.username} is a super admin and added this switch "
                    f"themselves. Their credentials cannot be changed.")
        return (f"{holder.username} already added this switch themselves. "
                f"Ask them to remove it first if it should be managed for them.")
    if existing.created_by == cu.username:
        return None                       # yours to manage
    if not overwrite_granted:
        return (f"{existing.created_by} already granted this switch to "
                f"{holder.username}. Confirm to take it over.")
    return None


def _probe_switch(ip: str, stype: str, ssh_username: str, password: str,
                  use_enable: bool, enable_password: Optional[str]) -> str:
    """Verify the credentials and read back the hostname, as a single add does."""
    return ssh_manager.fetch_hostname(ssh_username, ip, password, stype,
                                      use_enable, enable_password)


@app.post("/api/switches/bulk")
async def bulk_add_switches(data: sch.SwitchBulkAdd,
                            cu: User = Depends(get_current_user),
                            db: Session = Depends(get_db)):
    """Add several switches at once, for yourself or for other people."""
    stype = validate_switch_type(data.switch_type, ALL_TYPES)
    if not data.ssh_password:
        raise ValidationError("The SSH password is required to connect.")
    if data.use_enable and not data.enable_password:
        raise ValidationError(
            "Enable password is required when 'Requires enable password' is checked.")

    ips, seen_ips = [], set()
    for raw in data.ip_addresses:
        ip = validate_ip(raw, "Switch IP address")
        if ip not in seen_ips:
            seen_ips.add(ip)
            ips.append(ip)
    if len(ips) > MAX_BULK_IPS:
        raise ValidationError(
            f"You can add at most {MAX_BULK_IPS} switches at a time.")

    people = _resolve_grant_targets(data, cu, db)
    ssh_username = data.ssh_username or cu.username
    site = sites.validate_site_for_user(db, cu.username, data.site)

    # Probe every IP once, in parallel — the credentials and hostname are the
    # same whoever the switch is being added for.
    loop = asyncio.get_event_loop()
    probes = await asyncio.gather(*[
        loop.run_in_executor(_switch_executor, _probe_switch, ip, stype,
                             ssh_username, data.ssh_password, data.use_enable,
                             data.enable_password)
        for ip in ips], return_exceptions=True)

    enc = encrypt_password(data.ssh_password) if data.save_password else None
    enc_enable = (encrypt_password(data.enable_password)
                  if (data.use_enable and data.enable_password) else None)

    results, added, updated = [], 0, 0
    for ip, probe in zip(ips, probes):
        if isinstance(probe, Exception):
            message = (str(probe) if isinstance(probe, ssh_manager.SSHError)
                       else "Could not reach this switch.")
            audit.log_error(db, cu.username, f"Could not add switch {ip}", message,
                            event_type=db_models.EV_WRITE_FAILED)
            results.append({"ip_address": ip, "status": "error",
                            "error": message, "targets": []})
            continue

        hostname = probe
        per_user = []
        for person in people:
            existing = db.query(Switch).filter(
                Switch.ip_address == ip,
                Switch.owner_username == person.username).first()
            conflict = _conflict_for(existing, person, cu, data.overwrite_granted)
            if conflict:
                per_user.append({"username": person.username, "status": "skipped",
                                 "error": conflict})
                continue

            access = (ACCESS_WRITE if person.username == cu.username
                      else _access_for(person, data.access_level))
            # A row you add for yourself is unrestricted; the setting only
            # governs what you hand to somebody else.
            terminal = (True if person.username == cu.username
                        else _terminal_for(access, data.terminal_access))
            # A row you add for yourself is your own, never a granted one.
            created_by = None if person.username == cu.username else cu.username

            if existing:
                if person.username == cu.username:
                    _claim_if_granted(existing, cu)
                existing.hostname = hostname
                existing.switch_type = stype
                existing.site = site or existing.site
                existing.use_enable = data.use_enable
                existing.ssh_username = ssh_username
                existing.access_level = access
                existing.terminal_access = terminal
                if person.username != cu.username:
                    existing.created_by = created_by
                if enc:
                    existing.saved_password = enc
                existing.saved_enable_password = (
                    enc_enable if data.use_enable else None)
                if stype != TYPE_NEXUS and existing.vpc_peer_id:
                    peer = db.query(Switch).filter(
                        Switch.id == existing.vpc_peer_id).first()
                    if peer:
                        peer.vpc_peer_id = None
                    existing.vpc_peer_id = None
                # The stored password changed, so any live session is stale.
                ssh_manager.invalidate_session(
                    existing.ssh_username or person.username, ip)
                per_user.append({"username": person.username, "status": "updated",
                                 "access_level": access, "terminal_access": terminal,
                                 "switch_id": existing.id})
                updated += 1
            else:
                row = Switch(ip_address=ip, hostname=hostname, switch_type=stype,
                             site=site, use_enable=data.use_enable,
                             ssh_username=ssh_username,
                             owner_username=person.username, saved_password=enc,
                             saved_enable_password=enc_enable,
                             created_by=created_by, access_level=access,
                             terminal_access=terminal)
                db.add(row)
                db.flush()
                per_user.append({"username": person.username, "status": "added",
                                 "access_level": access, "terminal_access": terminal,
                                 "switch_id": row.id})
                added += 1

        results.append({"ip_address": ip, "hostname": hostname,
                        "status": "ok" if any(r["status"] != "skipped"
                                              for r in per_user) else "skipped",
                        "targets": per_user})
    db.commit()

    failed = [r for r in results if r["status"] == "error"]
    skipped = sum(1 for r in results for t in r["targets"]
                  if t["status"] == "skipped")
    others = [p.username for p in people if p.username != cu.username]
    # What was asked for is not always what was given: a plain user is forced
    # down to read, so a mixed group does not all get the level named in the
    # request. Recording only the request would overstate what some of them got.
    levels = sorted({t["access_level"] for r in results for t in r["targets"]
                     if t.get("access_level")})
    granted_levels = ", ".join(levels) or "none"
    if others:
        audit.log_success(
            db, cu.username,
            f"Added {added + updated} switch entr"
            f"{'y' if added + updated == 1 else 'ies'} for {len(others)} user(s)",
            f"IPs: {', '.join(ips)}\nFor: {', '.join(others)}\n"
            f"Access requested: {data.access_level or ACCESS_WRITE} · "
            f"granted: {granted_levels} · "
            f"{added} added, {updated} updated, {skipped} skipped, "
            f"{len(failed)} unreachable",
            event_type=db_models.EV_SWITCH_ADMIN)
    else:
        audit.log_success(
            db, cu.username,
            f"Added {added + updated} switch{'' if added + updated == 1 else 'es'}",
            f"IPs: {', '.join(ips)}\n{added} added, {updated} updated, "
            f"{len(failed)} unreachable",
            event_type=db_models.EV_SWITCH_ADMIN)

    return {"results": results, "added": added, "updated": updated,
            "skipped": skipped, "failed": len(failed),
            "usernames": [p.username for p in people]}


@app.get("/api/switches/granted")
async def list_granted_switches(cu: User = Depends(require_super_admin),
                                db: Session = Depends(get_db)):
    """Switches this super admin added for other people — the ones they may edit."""
    rows = db.query(Switch).filter(Switch.created_by == cu.username)\
                           .order_by(Switch.owner_username, Switch.ip_address).all()
    roles = _roles_by_username(db)
    return {"switches": [{
        "id": s.id, "ip_address": s.ip_address, "hostname": s.hostname,
        "switch_type": (s.switch_type or "ios").lower(), "site": s.site,
        "owner_username": s.owner_username, "ssh_username": s.ssh_username,
        "access_level": _effective_access(s, roles.get(s.owner_username)),
        "terminal_access": _effective_terminal(s, roles.get(s.owner_username)),
        "use_enable": bool(s.use_enable),
        "has_saved_password": bool(s.saved_password),
    } for s in rows]}


def _granted_switch_or_404(switch_id: int, cu: User, db: Session) -> Switch:
    row = db.query(Switch).filter(Switch.id == switch_id).first()
    if row is None:
        raise HTTPException(404, "That switch no longer exists.")
    if row.created_by != cu.username:
        # Includes your own switches: those are edited through the normal
        # switch endpoints, not this one.
        raise HTTPException(
            403, "You can only edit switches you added for someone else.")
    return row


@app.put("/api/switches/granted/{switch_id}")
async def update_granted_switch(switch_id: int, data: sch.GrantedSwitchUpdate,
                                cu: User = Depends(require_super_admin),
                                db: Session = Depends(get_db)):
    """Change the credentials or the privilege of a switch you granted."""
    row = _granted_switch_or_404(switch_id, cu, db)
    holder = get_user(db, row.owner_username)
    if holder is None:
        raise HTTPException(404, "The user this switch belongs to no longer exists.")

    changes = []
    if data.access_level is not None:
        access = _access_for(holder, data.access_level)
        if access != (row.access_level or ACCESS_WRITE):
            changes.append(f"access {row.access_level} → {access}")
            row.access_level = access
    # Resolved against the level the switch ends up on, so dropping a grant to
    # read-only takes the terminal with it even when the box was left ticked.
    if data.access_level is not None or data.terminal_access is not None:
        terminal = _terminal_for(row.access_level or ACCESS_WRITE,
                                 data.terminal_access)
        if terminal != (row.terminal_access is not False):
            changes.append("terminal access "
                           + ("granted" if terminal else "withdrawn"))
            row.terminal_access = terminal
    if data.ssh_username:
        if data.ssh_username != row.ssh_username:
            changes.append(f"ssh user {row.ssh_username} → {data.ssh_username}")
            row.ssh_username = data.ssh_username
    if data.ssh_password:
        row.saved_password = encrypt_password(data.ssh_password)
        changes.append("SSH password replaced")
    if data.use_enable is not None:
        row.use_enable = data.use_enable
        if not data.use_enable:
            row.saved_enable_password = None
            changes.append("enable password cleared")
    if data.enable_password:
        row.saved_enable_password = encrypt_password(data.enable_password)
        changes.append("enable password replaced")

    if not changes:
        return {"message": "Nothing was changed.", "changed": False}

    db.commit()
    # Credentials or privilege changed, so a session opened under the old ones
    # must not keep working.
    ssh_manager.invalidate_session(row.ssh_username or row.owner_username,
                                   row.ip_address)
    label = row.hostname or row.ip_address
    audit.log_success(
        db, cu.username,
        f"Updated {row.owner_username}'s switch {label}",
        " · ".join(changes), switch_id=row.id,
        event_type=db_models.EV_SWITCH_ADMIN)
    return {"message": f"Updated {row.owner_username}'s access to '{label}'.",
            "changed": True}


@app.delete("/api/switches/granted/{switch_id}")
async def delete_granted_switch(switch_id: int,
                                cu: User = Depends(require_super_admin),
                                db: Session = Depends(get_db)):
    """Take back a switch you granted."""
    row = _granted_switch_or_404(switch_id, cu, db)
    label = row.hostname or row.ip_address
    owner, ip = row.owner_username, row.ip_address
    ssh_manager.invalidate_session(row.ssh_username or owner, ip)
    db.query(Switch).filter(Switch.vpc_peer_id == row.id).update(
        {"vpc_peer_id": None}, synchronize_session=False)
    db.query(SwitchHealth).filter(SwitchHealth.switch_id == row.id).delete()
    db.delete(row)
    db.commit()
    audit.log_warn(db, cu.username, f"Removed {owner}'s switch {label}",
                   f"IP {ip}", event_type=db_models.EV_SWITCH_ADMIN)
    return {"message": f"'{label}' was removed from {owner}'s switches."}


# ═══════════════════════ DASHBOARD (super admin) ═══════════════════════
#
# Two halves with very different costs, deliberately kept apart:
#   · activity  — pure SQL over audit_logs. No SSH, so it is always instant.
#   · health    — needs SSH, so it is never collected on page load. A sweep
#                 writes snapshots and the dashboard reads only those.

DASHBOARD_WINDOWS = {"1h": timedelta(hours=1), "24h": timedelta(days=1),
                     "7d": timedelta(days=7), "30d": timedelta(days=30)}

# Separate from _switch_executor on purpose. That pool backs every interactive
# analysis endpoint; a sweep holding all ten of its workers for the length of a
# 90s running-config pull would stall every other user's ACL check behind it.
_health_executor = ThreadPoolExecutor(max_workers=4,
                                      thread_name_prefix="fleet-health")
_health_sweep_lock = threading.Lock()


def _window_delta(window: Optional[str]) -> Tuple[str, timedelta]:
    key = (window or "24h").lower()
    if key not in DASHBOARD_WINDOWS:
        raise ValidationError(
            "Window must be one of: " + ", ".join(DASHBOARD_WINDOWS))
    return key, DASHBOARD_WINDOWS[key]


def _bucket_plan(window: str) -> Tuple[int, timedelta]:
    """(bucket count, bucket size) for the activity bar strip."""
    return {"1h": (12, timedelta(minutes=5)),
            "24h": (24, timedelta(hours=1)),
            "7d": (7, timedelta(days=1)),
            "30d": (30, timedelta(days=1))}[window]


ACTIVITY_KINDS = {
    "changes":           lambda r: r.event_type in WRITE_EVENT_TYPES,
    "rules_added":       lambda r: r.event_type == db_models.EV_RULE_ADD,
    "rules_removed":     lambda r: r.event_type == db_models.EV_RULE_DELETE,
    "failed_operations": lambda r: (r.level or "") == "ERROR",
    "failed_logins":     lambda r: r.event_type == db_models.EV_LOGIN_FAILED,
}

# With no session store, a token stays valid until it expires, so presence can
# only be inferred from recent traffic. The idle-logout setting is the app's
# own definition of "still there"; without one, fall back to a quarter hour.
DEFAULT_PRESENCE_MINUTES = 15


def _presence_cutoff(db: Session) -> datetime:
    minutes = get_app_settings(db).idle_timeout_minutes or DEFAULT_PRESENCE_MINUTES
    return datetime.utcnow() - timedelta(minutes=minutes)


def _effective_access(switch: Switch, owner_role: Optional[str]) -> str:
    """What this switch's owner can actually do with it.

    The stored level is not the last word. No write feature in the app is open
    to a plain user — every write endpoint is behind require_admin — so for
    that role the answer is read-only whatever the column says. Grants already
    force the level down (see _access_for), but a switch somebody registered
    themselves takes the column's `write` default, and an account demoted to
    `user` keeps whatever it had. Reporting either as write access would be
    describing something nobody can use.
    """
    if owner_role == ROLE_USER:
        return ACCESS_READ
    return (switch.access_level or ACCESS_WRITE).lower()


def _effective_terminal(switch: Switch, owner_role: Optional[str]) -> bool:
    """Whether this switch's owner may open a terminal to it.

    Follows the effective access rather than the column alone, so anything that
    makes the switch read-only — including the owner's role — takes the
    terminal with it.
    """
    if _effective_access(switch, owner_role) == ACCESS_READ:
        return False
    # None is a row that predates the column, and those all had a terminal.
    return switch.terminal_access is not False


def _roles_by_username(db: Session) -> Dict[str, str]:
    return dict(db.query(User.username, User.role).all())


def _visible_switches(cu: User, db: Session) -> List[Switch]:
    """The switch inventory this caller may see.

    A super admin sees every account's; anyone else sees only their own. The
    same physical switch registered by two people is two entries here, not
    one — each carries its own credentials, access level and location, and
    collapsing them would hide that two accounts can reach the same device.
    """
    q = db.query(Switch)
    if cu.role != ROLE_SUPER_ADMIN:
        q = q.filter(Switch.owner_username == cu.username)
    return q.order_by(Switch.owner_username, Switch.id).all()


def _signed_in_users(db: Session) -> List[Dict[str, Any]]:
    cutoff = _presence_cutoff(db)
    users = db.query(User).filter(User.last_seen.isnot(None),
                                  User.last_seen >= cutoff)\
                          .order_by(User.last_seen.desc()).all()
    # Every address the account has been active from inside the same window,
    # not just the latest: somebody signed in from two places is signed in
    # from two places, and collapsing that to one address would hide it.
    return [{"username": u.username, "role": u.role,
             "last_seen": u.last_seen.isoformat(),
             "ips": active_ips_since(u, cutoff)} for u in users]


def _activity_slice(window: str, start: Optional[str], end: Optional[str]
                    ) -> Tuple[datetime, datetime]:
    """
    The bar strip always covers the whole window; start/end optionally narrow
    what the tiles and lists count, so clicking one bar re-reads the page for
    that slice without losing the surrounding context.
    """
    now = datetime.utcnow()
    _, delta = _window_delta(window)
    if not start and not end:
        return now - delta, now
    try:
        from_at = datetime.fromisoformat(start.replace("Z", "")) if start else now - delta
        to_at = datetime.fromisoformat(end.replace("Z", "")) if end else now
    except ValueError:
        raise ValidationError("Start and end must be ISO timestamps.")
    if to_at <= from_at:
        raise ValidationError("The end of the range must be after its start.")
    return from_at, to_at


def _log_entry(r: AuditLog, labels: Dict[int, str]) -> Dict[str, Any]:
    return {
        "id": r.id,
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "level": r.level, "username": r.username, "message": r.message,
        "description": r.description,
        "event_type": r.event_type,
        "ip_address": r.ip_address,
        "switch_label": labels.get(r.switch_id),
    }


def _switch_labels(db: Session) -> Dict[int, str]:
    # Independent of ownership: activity spans every user, so a log entry can
    # reference a switch this super admin does not own.
    return {sid: (hostname or ip) for sid, hostname, ip in
            db.query(Switch.id, Switch.hostname, Switch.ip_address).all()}


@app.get("/api/dashboard/activity")
async def dashboard_activity(window: str = "24h",
                             start: Optional[str] = None,
                             end: Optional[str] = None,
                             cu: User = Depends(require_admin),
                             db: Session = Depends(get_db)):
    """Rule-change activity. Regular admins only see their own log entries and
    their own switch inventory; super admins see everyone's logs and everyone's
    inventory. "unsaved" stays the caller's own either way — it is a list of
    configs *you* still have to write, not a fleet-wide count."""
    window, delta = _window_delta(window)
    now = datetime.utcnow()
    from_at, to_at = _activity_slice(window, start, end)

    # One read covering the whole window, so the bar strip and the (possibly
    # narrower) tiles come from the same query.
    span_from = min(from_at, now - delta)
    rows = db.query(AuditLog).filter(AuditLog.timestamp >= span_from,
                                     AuditLog.timestamp <= max(to_at, now))\
                             .order_by(AuditLog.timestamp.desc()).all()
    if cu.role != ROLE_SUPER_ADMIN:
        rows = [r for r in rows if r.username == cu.username]
    labels = _switch_labels(db)

    in_slice = [r for r in rows
                if r.timestamp and from_at <= r.timestamp <= to_at]
    writes = [r for r in in_slice if r.event_type in WRITE_EVENT_TYPES]

    my_switches = db.query(Switch).filter(Switch.owner_username == cu.username)\
                                  .order_by(Switch.id).all()
    switch_count = len(_visible_switches(cu, db))
    unsaved = [s for s in my_switches if _switch_pending_changes(db, s)]
    signed_in = _signed_in_users(db)

    kpis = {
        "changes": len(writes),
        "rules_added": sum(1 for r in writes
                           if r.event_type == db_models.EV_RULE_ADD),
        "rules_removed": sum(1 for r in writes
                             if r.event_type == db_models.EV_RULE_DELETE),
        "failed_operations": sum(1 for r in in_slice if (r.level or "") == "ERROR"),
        "failed_logins": sum(1 for r in in_slice
                             if r.event_type == db_models.EV_LOGIN_FAILED),
        # Signed-in describes who's here right now, across everyone — the one
        # tile that stays global regardless of role.
        "signed_in": len(signed_in),
        # Inventory, not activity: everyone's for a super admin, the caller's
        # own for a plain admin.
        "switches": switch_count,
        "unsaved": len(unsaved),
    }

    bucket_count, bucket_size = _bucket_plan(window)
    # Snapped to the bucket grid rather than "now" to the microsecond: the
    # bar strip is re-fetched on every click (to narrow the tiles to that
    # bucket), and unaligned boundaries would give each fetch a slightly
    # different `start` for the same bucket, so the UI could never recognise
    # it as still selected.
    # Rounded up, not down — rounding down would let the most recent bucket's
    # end fall short of `now` and silently drop the newest events from the
    # bar strip's sum.
    bucket_seconds = bucket_size.total_seconds()
    epoch = datetime(1970, 1, 1)
    aligned_now = epoch + timedelta(
        seconds=math.ceil((now - epoch).total_seconds() / bucket_seconds) * bucket_seconds)
    origin = aligned_now - bucket_size * bucket_count
    buckets = [{"start": (origin + bucket_size * i).isoformat(),
                "end": (origin + bucket_size * (i + 1)).isoformat(),
                "count": 0} for i in range(bucket_count)]
    for r in rows:
        if r.event_type not in WRITE_EVENT_TYPES or r.timestamp is None:
            continue
        if r.timestamp < origin:
            continue
        index = int((r.timestamp - origin) / bucket_size)
        if 0 <= index < bucket_count:
            buckets[index]["count"] += 1

    # The two feeds: what was done, and who was here. Already scoped to the
    # caller via the `rows` filter above for non-super-admins.
    recent_actions = [_log_entry(r, labels) for r in in_slice
                      if r.event_type in WRITE_EVENT_TYPES][:100]
    recent_activity = [_log_entry(r, labels) for r in in_slice][:100]

    pending_saves = [{
        "switch_id": s.id, "switch_label": s.hostname or s.ip_address,
        "site": s.site, "owner": s.owner_username,
    } for s in unsaved]
    if unsaved:
        last_write = dict(db.query(
            AuditLog.switch_id, func.max(AuditLog.timestamp)).filter(
                AuditLog.switch_id.in_([s.id for s in unsaved]),
                AuditLog.event_type.in_(WRITE_EVENT_TYPES)
            ).group_by(AuditLog.switch_id).all())
        for row in pending_saves:
            stamp = last_write.get(row["switch_id"])
            row["last_change_at"] = stamp.isoformat() if stamp else None

    return {
        "window": window,
        "generated_at": now.isoformat(),
        "range": {"start": from_at.isoformat(), "end": to_at.isoformat(),
                  "sliced": bool(start or end)},
        "kpis": kpis,
        "buckets": buckets,
        "bucket_seconds": int(bucket_size.total_seconds()),
        "recent_actions": recent_actions,
        "recent_activity": recent_activity,
        "signed_in": signed_in,
        "pending_saves": pending_saves,
    }


@app.get("/api/dashboard/activity/detail")
async def dashboard_activity_detail(kind: str, window: str = "24h",
                                    start: Optional[str] = None,
                                    end: Optional[str] = None,
                                    cu: User = Depends(require_admin),
                                    db: Session = Depends(get_db)):
    """The entries behind one dashboard tile, so a number can be opened up.
    Scoped exactly like the tile it came from: "switches" and log entries
    widen to every account for a super admin, "unsaved" stays the caller's
    own work list."""
    if kind == "signed_in":
        return {"kind": kind, "users": _signed_in_users(db), "entries": []}
    if kind in ("unsaved", "switches"):
        visible = _visible_switches(cu, db)
        # Peers are labelled only from what the caller may already see, so a
        # plain admin never learns the hostname of somebody else's switch.
        by_id = {s.id: s for s in visible}
        if kind == "unsaved":
            owned = [s for s in visible if s.owner_username == cu.username]
            rows = [s for s in owned if _switch_pending_changes(db, s)]
        else:
            rows = visible

        def _peer_label(s: Switch) -> Optional[str]:
            peer = by_id.get(s.vpc_peer_id) if s.vpc_peer_id else None
            return (peer.hostname or peer.ip_address) if peer else None

        roles = _roles_by_username(db)
        switches = [{
            "switch_id": s.id, "switch_label": s.hostname or s.ip_address,
            "site": s.site, "owner": s.owner_username,
            "switch_type": (s.switch_type or "ios").lower(),
            "ip_address": s.ip_address,
            "access_level": _effective_access(s, roles.get(s.owner_username)),
            "terminal_access": _effective_terminal(s, roles.get(s.owner_username)),
            "vpc_peer_label": _peer_label(s),
        } for s in rows]
        if kind == "unsaved" and rows:
            last_write = dict(db.query(
                AuditLog.switch_id, func.max(AuditLog.timestamp)).filter(
                    AuditLog.switch_id.in_([s.id for s in rows]),
                    AuditLog.event_type.in_(WRITE_EVENT_TYPES)
                ).group_by(AuditLog.switch_id).all())
            for row in switches:
                stamp = last_write.get(row["switch_id"])
                row["last_change_at"] = stamp.isoformat() if stamp else None
        return {"kind": kind, "entries": [], "switches": switches}

    matches = ACTIVITY_KINDS.get(kind)
    if matches is None:
        raise ValidationError("Unknown detail kind: " + kind)

    window, _ = _window_delta(window)
    from_at, to_at = _activity_slice(window, start, end)
    rows = db.query(AuditLog).filter(AuditLog.timestamp >= from_at,
                                     AuditLog.timestamp <= to_at)\
                             .order_by(AuditLog.timestamp.desc()).all()
    if cu.role != ROLE_SUPER_ADMIN:
        rows = [r for r in rows if r.username == cu.username]
    labels = _switch_labels(db)
    entries = [_log_entry(r, labels) for r in rows if matches(r)]
    return {"kind": kind, "entries": entries[:300], "total": len(entries)}


def _health_row(switch: Switch, snapshot: Optional[SwitchHealth],
                now: datetime) -> Dict[str, Any]:
    base = {
        "switch_id": switch.id,
        "switch_label": switch.hostname or switch.ip_address,
        "switch_ip": switch.ip_address,
        "switch_type": (switch.switch_type or "ios").lower(),
        "site": switch.site,
        "vpc_peer_id": switch.vpc_peer_id,
    }
    if snapshot is None:
        # Shown rather than omitted: a switch nobody has swept is a gap in
        # coverage, not an absence of findings.
        base.update({"status": "never_scanned", "error": None,
                     "collected_at": None, "age_seconds": None, "tcam": None})
        return base
    base.update({
        "status": snapshot.status,
        "error": snapshot.error,
        "collected_at": snapshot.collected_at.isoformat() if snapshot.collected_at else None,
        "age_seconds": (int((now - snapshot.collected_at).total_seconds())
                        if snapshot.collected_at else None),
        "scanned_by": snapshot.scanned_by,
        "duration_ms": snapshot.duration_ms,
        "acl_count": snapshot.acl_count,
        "rule_count": snapshot.rule_count,
        "object_group_count": snapshot.object_group_count,
        "redundant_count": snapshot.redundant_count,
        "trailing_redundant_count": snapshot.trailing_redundant_count,
        "wrong_direction_count": snapshot.wrong_direction_count,
        "summarizable_count": snapshot.summarizable_count,
        "summary_suggestion_count": snapshot.summary_suggestion_count,
        "time_ranges_total": snapshot.time_ranges_total,
        "time_ranges_inactive": snapshot.time_ranges_inactive,
        "time_ranges_expired": snapshot.time_ranges_expired,
        "rules_with_dead_schedule": snapshot.rules_with_dead_schedule,
        "vpc_sync_status": snapshot.vpc_sync_status,
        "vpc_mismatch_count": snapshot.vpc_mismatch_count,
        "vpc_binding_mismatch_count": snapshot.vpc_binding_mismatch_count,
        "tcam": {
            "status": snapshot.tcam_status,
            "source": snapshot.tcam_source,
            "error": snapshot.tcam_error,
            "max": snapshot.tcam_max,
            "ingress": {"used": snapshot.tcam_in_used,
                        "free": snapshot.tcam_in_free,
                        "percent": snapshot.tcam_in_pct},
            "egress": {"used": snapshot.tcam_out_used,
                       "free": snapshot.tcam_out_free,
                       "percent": snapshot.tcam_out_pct},
        },
        # switch_type is user-supplied and never checked against the device.
        # When the TCAM reply came from the other platform's command, it is
        # wrong — the only validation available for that field.
        "type_mismatch": bool(snapshot.tcam_source and
                              snapshot.tcam_source != (switch.switch_type or "ios").lower()),
    })
    return base


def _health_payload(cu: User, db: Session) -> Dict[str, Any]:
    now = datetime.utcnow()
    switches = db.query(Switch).filter(
        Switch.owner_username == cu.username).order_by(Switch.id).all()
    snapshots = {s.switch_id: s for s in db.query(SwitchHealth).filter(
        SwitchHealth.switch_id.in_([s.id for s in switches]))} if switches else {}
    rows = [_health_row(s, snapshots.get(s.id), now) for s in switches]

    scanned = [r for r in rows if r["status"] != "never_scanned"]
    healthy = [r for r in rows if r["status"] == HEALTH_OK]

    def total(field):
        return sum(r.get(field) or 0 for r in healthy)

    percents = [p for r in healthy for p in
                ((r["tcam"] or {}).get("ingress", {}).get("percent"),
                 (r["tcam"] or {}).get("egress", {}).get("percent")) if p is not None]
    collected = [r["collected_at"] for r in scanned if r["collected_at"]]

    return {
        "switches": rows,
        "totals": {
            "switch_count": len(rows),
            "scanned_count": len(scanned),
            "never_scanned_count": len(rows) - len(scanned),
            "error_count": sum(1 for r in scanned
                               if r["status"] in (HEALTH_ERROR, HEALTH_NO_CREDENTIALS)),
            "partial_count": sum(1 for r in scanned if r["status"] == "partial"),
            # Summed over healthy rows only: a failed fetch reports zero, and
            # that zero is not a fact about the switch.
            "redundant_count": total("redundant_count"),
            "trailing_redundant_count": total("trailing_redundant_count"),
            "wrong_direction_count": total("wrong_direction_count"),
            "summarizable_count": total("summarizable_count"),
            "time_ranges_expired": total("time_ranges_expired"),
            "rules_with_dead_schedule": total("rules_with_dead_schedule"),
            "tcam_unsupported_count": sum(
                1 for r in healthy
                if (r["tcam"] or {}).get("status") == TCAM_UNSUPPORTED),
            "worst_tcam_percent": max(percents) if percents else None,
            "type_mismatch_count": sum(1 for r in rows if r.get("type_mismatch")),
        },
        "last_collected_at": max(collected) if collected else None,
        "sweep_running": _health_sweep_lock.locked(),
    }


@app.get("/api/dashboard/health")
async def dashboard_health(cu: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    """Per-switch health from the last sweep. Reads snapshots only — no SSH."""
    return _health_payload(cu, db)


def _write_snapshot(row: Dict[str, Any], username: str):
    """Upsert one switch's snapshot from its own session — sweep workers run in
    threads, and a SQLite session cannot be shared across them."""
    session = SessionLocal()
    try:
        snapshot = session.query(SwitchHealth).filter(
            SwitchHealth.switch_id == row["switch_id"]).first()
        if snapshot is None:
            snapshot = SwitchHealth(switch_id=row["switch_id"])
            session.add(snapshot)
        snapshot.collected_at = datetime.utcnow()
        snapshot.scanned_by = username
        for column in SwitchHealth.__table__.columns.keys():
            if column in ("id", "switch_id", "collected_at", "scanned_by"):
                continue
            if column in row:
                setattr(snapshot, column, row[column])
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()


def _collect_and_store(target, username: str) -> Dict[str, Any]:
    """One sweep worker: collect, hand back any SSH session it opened, store."""
    had_session = ssh_manager.has_session(target.ssh_username, target.ip)
    try:
        row = health_collector.collect_one(target, username)
    finally:
        if not had_session:
            # Sessions are never evicted, so without this a fleet sweep leaves
            # one open connection and VTY line per switch, permanently.
            try:
                ssh_manager.invalidate_session(target.ssh_username, target.ip)
            except Exception:
                pass
    return row, row.pop("_acl_map", {}), row.pop("_iface_map", {})


def _apply_vpc_sync(rows: List[Dict[str, Any]], acl_maps: Dict[int, Dict[str, Any]],
                    iface_maps: Dict[int, Dict[str, Any]], peers: Dict[int, int]):
    """
    Diff each VPC pair once, from data both switches already returned.

    Matches what the VPC Sync page reports: a pair is out of sync when their
    ACL rules differ *or* when the same ACL is bound to different VLANs or in
    different directions. Checking only the rules would call a pair in sync
    while one of them applies an ACL nowhere.
    """
    by_id = {r["switch_id"]: r for r in rows}
    done = set()
    for switch_id, peer_id in peers.items():
        pair = (min(switch_id, peer_id), max(switch_id, peer_id))
        if pair in done or peer_id not in by_id or switch_id not in by_id:
            continue
        done.add(pair)
        if switch_id not in acl_maps or peer_id not in acl_maps:
            continue
        acl_diffs = [d for d in acl_parser.diff_acl_sets(
            acl_maps[switch_id], acl_maps[peer_id]) if d["status"] != "match"]
        binding_diffs = acl_parser.diff_vlan_acl_bindings(
            acl_parser.vlan_bindings_only(iface_maps.get(switch_id, {})),
            acl_parser.vlan_bindings_only(iface_maps.get(peer_id, {})))
        for member_id in (switch_id, peer_id):
            by_id[member_id]["vpc_peer_id"] = (
                peer_id if member_id == switch_id else switch_id)
            by_id[member_id]["vpc_sync_status"] = (
                "match" if not (acl_diffs or binding_diffs) else "mismatch")
            by_id[member_id]["vpc_mismatch_count"] = len(acl_diffs)
            by_id[member_id]["vpc_binding_mismatch_count"] = len(binding_diffs)


@app.post("/api/dashboard/health/scan")
async def dashboard_health_scan(data: sch.DashboardScanRequest,
                                cu: User = Depends(require_admin),
                                db: Session = Depends(get_db)):
    """Sweep switches over SSH and store a fresh snapshot for each."""
    if not _health_sweep_lock.acquire(blocking=False):
        raise HTTPException(409, "A health scan is already running.")
    try:
        query = db.query(Switch).filter(Switch.owner_username == cu.username)
        if data.switch_ids:
            query = query.filter(Switch.id.in_(data.switch_ids))
        switches = query.order_by(Switch.id).all()
        if not switches:
            raise HTTPException(404, "No switches to scan.")

        targets, rows = [], []
        for switch in switches:
            try:
                # One id at a time: resolve_targets caps at two and demands
                # all-Nexus for a pair, neither of which suits a fleet sweep.
                targets.append(svc.resolve_targets([switch.id], cu.username, db)[0])
            except HTTPException as exc:
                row = {"switch_id": switch.id, "status": HEALTH_NO_CREDENTIALS,
                       "error": str(exc.detail)}
                row.update(health_collector._zero_counts())
                # Clear the whole TCAM block, not just its status, so a switch
                # that used to scan cleanly does not keep showing yesterday's
                # numbers after its password is removed.
                row.update(health_collector._tcam_columns(
                    {"status": TCAM_UNSUPPORTED, "reason": str(exc.detail),
                     "source": None, "ingress": {}, "egress": {}}))
                rows.append(row)

        peers = {s.id: s.vpc_peer_id for s in switches if s.vpc_peer_id}
        loop = asyncio.get_event_loop()
        started = time.monotonic()
        collected = await asyncio.gather(*[
            loop.run_in_executor(_health_executor, _collect_and_store,
                                 target, cu.username)
            for target in targets])
        duration = time.monotonic() - started

        acl_maps, iface_maps = {}, {}
        for row, acl_map, iface_map in collected:
            rows.append(row)
            acl_maps[row["switch_id"]] = acl_map
            iface_maps[row["switch_id"]] = iface_map
        _apply_vpc_sync(rows, acl_maps, iface_maps, peers)

        for row in rows:
            _write_snapshot(row, cu.username)

        ok = sum(1 for r in rows if r["status"] == HEALTH_OK)
        failed = len(rows) - ok
        audit.log_info(
            db, cu.username,
            f"Ran a fleet health scan on {len(rows)} switch"
            f"{'es' if len(rows) != 1 else ''}",
            f"Completed in {duration:.1f}s. {ok} healthy, {failed} with problems.",
                       event_type=db_models.EV_ANALYSIS)

        payload = _health_payload(cu, db)
        payload["sweep"] = {"duration_seconds": round(duration, 1),
                            "scanned": len(rows), "ok": ok, "failed": failed}
        return payload
    finally:
        _health_sweep_lock.release()


# ═══════════════════════ SWITCHES ═══════════════════════

def _latest_switch_log(db: Session, switch_id: int, username: str,
                       message_prefix: str) -> Optional[AuditLog]:
    return db.query(AuditLog).filter(
        AuditLog.switch_id == switch_id,
        AuditLog.username == username,
        AuditLog.message.startswith(message_prefix),
    ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()


def _log_is_newer(candidate: Optional[AuditLog],
                  checkpoint: Optional[AuditLog]) -> bool:
    if candidate is None or checkpoint is None:
        return False
    return (candidate.timestamp, candidate.id) > (
        checkpoint.timestamp, checkpoint.id)


def _switch_pending_changes(db: Session, s: Switch) -> bool:
    """Match the Logs UI's Undo-button condition exactly. Partial or legacy
    audit records must not make a switch appear unsaved when there is no
    corresponding Undo action available to the owner. This is the real
    unsaved signal — the Switch.pending_changes column is not kept in sync
    by any write path and must not be used."""
    latest_undoable = db.query(AuditLog).filter(
        AuditLog.switch_id == s.id,
        AuditLog.username == s.owner_username,
        AuditLog.undo_commands.isnot(None),
        AuditLog.undo_commands != "",
        AuditLog.undo_label.isnot(None),
        AuditLog.undo_label != "",
    ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
    latest_save = _latest_switch_log(
        db, s.id, s.owner_username, "Saved configuration on ")
    has_unsaved_undoable = (
        latest_undoable is not None and
        (latest_save is None or _log_is_newer(latest_undoable, latest_save)))
    latest_saved_undo = _latest_switch_log(
        db, s.id, s.owner_username, "Undid a saved change on ")
    changed_after_save = _log_is_newer(latest_saved_undo, latest_save)
    return has_unsaved_undoable or changed_after_save


def _switch_out(s: Switch, by_id: Dict[int, Switch], db: Session,
                owner_role: Optional[str] = None) -> sch.SwitchResponse:
    peer = by_id.get(s.vpc_peer_id) if s.vpc_peer_id else None
    return sch.SwitchResponse(
        id=s.id, ip_address=s.ip_address, hostname=s.hostname,
        switch_type=s.switch_type, site=s.site,
        use_enable=bool(s.use_enable),
        ssh_username=s.ssh_username,
        has_saved_password=bool(s.saved_password),
        vpc_peer_id=s.vpc_peer_id,
        vpc_peer_name=(peer.hostname or peer.ip_address) if peer else None,
        pending_changes=_switch_pending_changes(db, s),
        created_by=s.created_by,
        access_level=_effective_access(s, owner_role),
        terminal_access=_effective_terminal(s, owner_role))


@app.get("/api/switches", response_model=List[sch.SwitchResponse])
async def list_switches(cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    rows = db.query(Switch).filter(Switch.owner_username == cu.username).all()
    by_id = {s.id: s for s in rows}
    rows.sort(key=lambda s: ((s.site or "zzz"), (s.hostname or s.ip_address).lower()))
    return [_switch_out(s, by_id, db, cu.role) for s in rows]


@app.put("/api/switches/order")
async def update_switch_order(data: sch.SwitchOrderUpdate,
                              cu: User = Depends(get_current_user),
                              db: Session = Depends(get_db)):
    """Persist this account's label and switch ordering preferences."""
    allowed_labels = set(sites.all_labels(db, cu.username)) | {""}
    labels = []
    seen_labels = set()
    for raw in data.labels:
        label = sites.normalise(raw) if raw else ""
        if label not in allowed_labels:
            raise ValidationError(f"Location '{raw}' is not one of your locations.")
        if label not in seen_labels:
            labels.append(label)
            seen_labels.add(label)

    owned_ids = {row[0] for row in db.query(Switch.id).filter(
        Switch.owner_username == cu.username).all()}
    switch_ids = []
    seen_ids = set()
    for switch_id in data.switch_ids:
        if switch_id not in owned_ids:
            raise ValidationError("The switch order contains a switch you do not own.")
        if switch_id not in seen_ids:
            switch_ids.append(switch_id)
            seen_ids.add(switch_id)

    # Append newly created labels/switches so old saved layouts remain valid.
    labels.extend(label for label in sites.all_labels(db, cu.username) + [""]
                  if label not in seen_labels)
    switch_ids.extend(switch_id for switch_id in sorted(owned_ids)
                      if switch_id not in seen_ids)
    layout = {"labels": labels, "switch_ids": switch_ids}
    cu.switch_layout = json.dumps(layout, separators=(",", ":"))
    db.commit()
    return {"message": "Switch order saved.", **layout}


@app.post("/api/switches")
async def add_switch(data: sch.SwitchAdd, cu: User = Depends(get_current_user),
                     db: Session = Depends(get_db)):
    ip    = validate_ip(data.ip_address, "Switch IP address")
    stype = validate_switch_type(data.switch_type, ALL_TYPES)
    site  = sites.validate_site_for_user(db, cu.username, data.site)
    if not data.ssh_password:
        raise ValidationError("The SSH password is required to connect.")
    
    # Validate enable password requirement
    if data.use_enable and not data.enable_password:
        raise ValidationError("Enable password is required when 'Requires enable password' is checked.")
    
    # Default ssh_username to current user if not provided
    ssh_username = data.ssh_username or cu.username

    try:
        hostname = await asyncio.to_thread(
            ssh_manager.fetch_hostname,
            ssh_username, ip, data.ssh_password, stype,
            data.use_enable, data.enable_password)
    except ssh_manager.SSHError as e:
        audit.log_error(db, cu.username, f"Could not add switch {ip}", str(e))
        raise HTTPException(502, str(e))

    existing = db.query(Switch).filter(
        Switch.ip_address == ip, Switch.owner_username == cu.username).first()
    enc = encrypt_password(data.ssh_password) if data.save_password else None
    enc_enable = encrypt_password(data.enable_password) if (data.use_enable and data.enable_password) else None

    if existing:
        if _claim_if_granted(existing, cu):
            audit.log_success(
                db, cu.username, f"Took over switch {hostname}",
                f"IP {ip} · connected with your own credentials, so it is now "
                f"your switch with {existing.access_level} access.",
                switch_id=existing.id, event_type=db_models.EV_SWITCH_ADMIN)
        existing.hostname    = hostname
        existing.switch_type = stype
        existing.site        = site or existing.site
        existing.use_enable  = data.use_enable
        existing.ssh_username = ssh_username
        if enc:
            existing.saved_password = enc
        # Save or clear enable password
        if data.use_enable and enc_enable:
            existing.saved_enable_password = enc_enable
        elif not data.use_enable:
            existing.saved_enable_password = None
        # Type change away from Nexus breaks any VPC pairing
        if stype != TYPE_NEXUS and existing.vpc_peer_id:
            peer = db.query(Switch).filter(Switch.id == existing.vpc_peer_id).first()
            if peer:
                peer.vpc_peer_id = None
            existing.vpc_peer_id = None
        db.commit()
        audit.log_info(db, cu.username, f"Updated switch {hostname}",
                       f"IP {ip} · type {stype} · site {site or 'unset'} · "
                       f"ssh_user {ssh_username} · enable {'yes' if data.use_enable else 'no'}")
        return {"message": f"Switch '{hostname}' was updated.",
                "hostname": hostname, "id": existing.id}

    s = Switch(ip_address=ip, hostname=hostname, switch_type=stype, site=site,
               use_enable=data.use_enable, ssh_username=ssh_username,
               owner_username=cu.username, saved_password=enc, 
               saved_enable_password=enc_enable)
    db.add(s); db.commit(); db.refresh(s)
    audit.log_success(db, cu.username, f"Added switch {hostname}",
                      f"IP {ip} · type {stype} · site {site or 'unset'} · "
                      f"ssh_user {ssh_username} · enable {'yes' if data.use_enable else 'no'}")
    return {"message": f"Switch '{hostname}' was added.",
            "hostname": hostname, "id": s.id}


def _claim_if_granted(row: Switch, user: User) -> bool:
    """
    Turn a granted switch into the holder's own, after their credentials have
    been verified against the device.

    Proving you can reach the switch yourself is the whole basis of the claim:
    the read-only restriction exists because the granter supplied the password,
    and it stops meaning anything once the holder supplies their own. A
    standard user stays read-only regardless, since no write feature is
    available to that role anyway.
    """
    if not row.created_by:
        return False
    row.created_by = None
    row.access_level = (ACCESS_READ if user.role == ROLE_USER else ACCESS_WRITE)
    row.terminal_access = row.access_level != ACCESS_READ
    return True


@app.put("/api/switches")
async def update_switch(data: sch.SwitchUpdate,
                        cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    """Update type / password / site / enable flag / ssh username without re-probing the switch."""
    s = db.query(Switch).filter(Switch.id == data.switch_id,
                                Switch.owner_username == cu.username).first()
    if not s:
        raise HTTPException(404, "That switch no longer exists.")

    changes = []
    
    # Check if enable is being turned ON and requires password
    enabling_enable = data.use_enable is True and not s.use_enable
    
    # If enabling enable mode, require enable password
    if enabling_enable and not data.enable_password:
        raise HTTPException(
            status_code=400,
            detail="Enable password is required when enabling 'Requires an enable password'."
        )
    
    # If use_enable is currently True and we're keeping it True, need enable password if changing other credentials
    if data.use_enable is True and not data.enable_password:
        # Check if we're changing SSH password or other settings that require testing
        if data.ssh_password:
            raise HTTPException(
                status_code=400,
                detail="Enable password is required to test the connection."
            )
    
    # Determine if we need to test the connection
    test_connection = False
    test_ssh_password = None
    test_enable_password = None
    
    # Test if SSH password is being changed
    if data.ssh_password:
        test_connection = True
        test_ssh_password = data.ssh_password
    # Test if enable is being turned ON (need to verify enable password works)
    elif enabling_enable:
        test_connection = True
        # Need existing SSH password to test
        if not s.saved_password:
            raise HTTPException(
                status_code=400,
                detail="Cannot verify enable password: no saved SSH password. Please provide the SSH password."
            )
        from switch_utils import decrypt_password
        test_ssh_password = decrypt_password(s.saved_password)
    
    if test_connection:
        # Determine enable password for testing
        ssh_username = s.ssh_username or cu.username
        switch_type = data.switch_type if data.switch_type is not None else (s.switch_type or "ios")
        use_enable_for_test = data.use_enable if data.use_enable is not None else bool(s.use_enable)
        
        if use_enable_for_test:
            test_enable_password = data.enable_password
            if not test_enable_password:
                raise HTTPException(
                    status_code=400,
                    detail="Enable password is required for testing connection."
                )
        
        try:
            # Invalidate any existing session first
            ssh_manager.invalidate_session(ssh_username, s.ip_address)
            # Test by fetching hostname
            await asyncio.to_thread(
                ssh_manager.fetch_hostname,
                username=ssh_username,
                switch_ip=s.ip_address,
                ssh_password=test_ssh_password,
                switch_type=switch_type,
                use_enable=use_enable_for_test,
                enable_password=test_enable_password,
            )
        except ssh_manager.SSHError as e:
            raise HTTPException(status_code=400, detail=str(e))
    
    # Handle switch type change
    if data.switch_type is not None:
        stype = validate_switch_type(data.switch_type, ALL_TYPES)
        if stype != s.switch_type:
            changes.append(f"type {s.switch_type or 'ios'} → {stype}")
            s.switch_type = stype
            # Type change away from Nexus breaks any VPC pairing
            if stype != TYPE_NEXUS and s.vpc_peer_id:
                peer = db.query(Switch).filter(Switch.id == s.vpc_peer_id).first()
                if peer:
                    peer.vpc_peer_id = None
                s.vpc_peer_id = None
                changes.append("VPC pairing cleared (no longer Nexus)")
    
    if data.site is not None:
        site = sites.validate_site_for_user(db, cu.username, data.site)
        if site != s.site:
            changes.append(f"site {s.site or 'unset'} → {site or 'unset'}")
            s.site = site
    if data.use_enable is not None and bool(data.use_enable) != bool(s.use_enable):
        changes.append(f"enable {'on' if data.use_enable else 'off'}")
        s.use_enable = bool(data.use_enable)
    # A verified credential change is the holder proving the switch is theirs.
    if test_connection and _claim_if_granted(s, cu):
        changes.append("took it over with your own credentials "
                       f"({s.access_level} access)")
    if data.ssh_username is not None and data.ssh_username != s.ssh_username:
        old_user = s.ssh_username or cu.username
        changes.append(f"SSH user {old_user} → {data.ssh_username}")
        # Invalidate session with old username
        ssh_manager.invalidate_session(old_user, s.ip_address)
        s.ssh_username = data.ssh_username
    if data.ssh_password:
        s.saved_password = encrypt_password(data.ssh_password)
        changes.append("SSH password replaced")
        # Invalidate session with current username
        ssh_manager.invalidate_session(s.ssh_username or cu.username, s.ip_address)
    
    # Handle enable password updates
    if data.use_enable is not None and data.use_enable and data.enable_password:
        # Save or update enable password
        s.saved_enable_password = encrypt_password(data.enable_password)
        changes.append("Enable password updated")
    elif data.use_enable is not None and not data.use_enable:
        # Clear enable password when disabling enable mode
        if s.saved_enable_password:
            s.saved_enable_password = None
            changes.append("Enable password cleared")

    if not changes:
        return {"message": "Nothing to change.", "changed": False}

    db.commit()
    label = s.hostname or s.ip_address
    audit.log_info(db, cu.username, f"Updated switch {label}", "; ".join(changes))
    return {"message": f"Switch '{label}' updated.", "changed": True}


@app.delete("/api/switches/{switch_id}")
async def delete_switch(switch_id: int, cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    s = db.query(Switch).filter(Switch.id == switch_id,
                                Switch.owner_username == cu.username).first()
    if not s:
        raise HTTPException(404, "That switch no longer exists.")
    label = s.hostname or s.ip_address
    db.query(Switch).filter(Switch.vpc_peer_id == switch_id)\
                    .update({"vpc_peer_id": None})
    ssh_manager.invalidate_session(cu.username, s.ip_address)
    db.delete(s); db.commit()
    audit.log_warn(db, cu.username, f"Removed switch {label}", f"IP {s.ip_address}")
    return {"message": f"Switch '{label}' was removed."}


@app.post("/api/switches/vpc-pair")
async def vpc_pair(data: sch.VpcPairRequest,
                   cu: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    s = db.query(Switch).filter(Switch.id == data.switch_id,
                                Switch.owner_username == cu.username).first()
    if not s:
        raise HTTPException(404, "That switch no longer exists.")
    if (s.switch_type or "").lower() != TYPE_NEXUS:
        raise ValidationError(
            f"'{s.hostname or s.ip_address}' is not a Nexus switch. "
            "Only Nexus switches can form a VPC pair.")

    label = s.hostname or s.ip_address

    if data.peer_switch_id is None:
        if not s.vpc_peer_id:
            return {"message": f"'{label}' has no VPC peer to remove.",
                    "changed": False}
        peer = db.query(Switch).filter(Switch.id == s.vpc_peer_id).first()
        peer_label = (peer.hostname or peer.ip_address) if peer else "unknown"
        if peer:
            peer.vpc_peer_id = None
        s.vpc_peer_id = None
        db.commit()
        audit.log_info(db, cu.username, f"Unpaired VPC for {label}",
                       f"Previous peer: {peer_label}")
        return {"message": f"VPC pairing removed from '{label}'.", "changed": True}

    peer = db.query(Switch).filter(Switch.id == data.peer_switch_id,
                                   Switch.owner_username == cu.username).first()
    if not peer:
        raise HTTPException(404, "The selected peer switch no longer exists.")
    if peer.id == s.id:
        raise ValidationError("A switch cannot be its own VPC peer.")
    if (peer.switch_type or "").lower() != TYPE_NEXUS:
        raise ValidationError(
            f"'{peer.hostname or peer.ip_address}' is not a Nexus switch.")

    peer_label = peer.hostname or peer.ip_address
    if s.vpc_peer_id == peer.id and peer.vpc_peer_id == s.id:
        return {"message": f"'{label}' and '{peer_label}' are already paired.",
                "changed": False}

    # Break any prior pairings on both sides
    for other_id in (s.vpc_peer_id, peer.vpc_peer_id):
        if other_id and other_id not in (s.id, peer.id):
            other = db.query(Switch).filter(Switch.id == other_id).first()
            if other:
                other.vpc_peer_id = None

    s.vpc_peer_id = peer.id
    peer.vpc_peer_id = s.id
    db.commit()
    audit.log_success(db, cu.username, f"Paired VPC {label} ↔ {peer_label}",
                      f"{s.ip_address} and {peer.ip_address}")
    return {"message": f"'{label}' and '{peer_label}' are now VPC peers.",
            "changed": True}


# ═══════════════════════ INTERACTIVE TERMINAL ═══════════════════════

def _require_terminal_access(switch: Switch, cu: User) -> None:
    """Refuse a terminal on a switch whose grant does not carry one.

    Checked here rather than only in the UI: hiding the button stops it being
    offered, but the session endpoint is what actually opens the connection.
    """
    if _effective_terminal(switch, cu.role):
        return
    label = switch.hostname or switch.ip_address
    raise HTTPException(
        403,
        f"You do not have terminal access to {label}. Ask the super admin who "
        "gave you this switch for it.")


@app.post("/api/terminal/sessions")
async def create_terminal_session(data: sch.SwitchTargets,
                                  cu: User = Depends(require_admin),
                                  db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)
    # A terminal is unrestricted access to the device, so read-only switches
    # are refused outright rather than filtered. A write grant can also have
    # had the terminal withheld on its own, which is refused the same way.
    for target in targets:
        svc.require_write_access(target)
        _require_terminal_access(target.sw, cu)
    workspace = terminal_service.reserve(cu.username, targets)
    labels = [target.label for target in workspace.targets]
    audit.log_success(
        db, cu.username, "Opened interactive terminal",
        "Switches: " + ", ".join(labels) +
        ". Interactive commands and output are not recorded.")
    return {
        "session_id": workspace.id,
        "switches": [
            {"id": target.switch_id, "name": target.label, "ip": target.ip,
             "switch_type": target.switch_type}
            for target in workspace.targets
        ],
    }


@app.delete("/api/terminal/sessions/{session_id}")
async def close_terminal_session(session_id: str,
                                 cu: User = Depends(require_admin),
                                 db: Session = Depends(get_db)):
    closed = terminal_service.close_owned(session_id, cu.username)
    if closed:
        audit.log_info(db, cu.username, "Closed interactive terminal", "")
    return {"closed": closed}


async def _terminal_send(websocket: WebSocket, send_lock: asyncio.Lock,
                         message: Dict[str, Any]):
    async with send_lock:
        await websocket.send_json(message)


async def _terminal_output_pump(websocket: WebSocket, send_lock: asyncio.Lock,
                                index: int, connection: ssh_manager.SSHSession):
    last_alive_check = 0.0
    loop = asyncio.get_running_loop()
    try:
        while True:
            output = await asyncio.to_thread(connection.read_channel)
            if output:
                await _terminal_send(websocket, send_lock, {
                    "type": "output", "terminal": index, "data": output})
            else:
                await asyncio.sleep(0.04)

            now = loop.time()
            if now - last_alive_check >= 1.0:
                last_alive_check = now
                if not await asyncio.to_thread(connection.is_interactive_alive):
                    break
    except (ssh_manager.SSHError, WebSocketDisconnect, RuntimeError):
        return
    try:
        await _terminal_send(websocket, send_lock, {
            "type": "status", "terminal": index, "status": "disconnected",
            "message": "SSH connection closed."})
    except (WebSocketDisconnect, RuntimeError):
        pass


async def _terminal_input_loop(websocket: WebSocket,
                               connections: Dict[int, ssh_manager.SSHSession]):
    while True:
        message = await websocket.receive_json()
        kind = message.get("type")
        if kind == "close":
            return
        try:
            index = int(message.get("terminal", 0))
        except (TypeError, ValueError):
            continue
        connection = connections.get(index)
        if not connection:
            continue
        if kind == "input":
            data = message.get("data", "")
            if isinstance(data, str) and len(data) <= 8192:
                try:
                    await asyncio.to_thread(connection.write_channel, data)
                except ssh_manager.SSHError:
                    # One VPC pane may close while its peer remains active.
                    connections.pop(index, None)
        elif kind == "resize":
            try:
                columns = max(20, min(300, int(message.get("cols", 80))))
                rows = max(5, min(120, int(message.get("rows", 24))))
            except (TypeError, ValueError):
                continue
            await asyncio.to_thread(connection.resize_terminal, columns, rows)


@app.websocket("/api/terminal/ws/{session_id}")
async def terminal_websocket(websocket: WebSocket, session_id: str):
    origin = websocket.headers.get("origin")
    request_host = websocket.headers.get("host", "").lower()
    if origin and urlparse(origin).netloc.lower() != request_host:
        await websocket.close(code=4403, reason="Cross-origin terminal access is forbidden.")
        return
    workspace = terminal_service.claim(session_id)
    if not workspace:
        await websocket.close(code=4404, reason="Terminal session is invalid or expired.")
        return

    await websocket.accept()
    send_lock = asyncio.Lock()
    connections: Dict[int, ssh_manager.SSHSession] = {}
    receiver = None
    pumps = set()
    try:
        await _terminal_send(websocket, send_lock, {
            "type": "session",
            "switches": [
                {"terminal": index, "name": target.label, "ip": target.ip}
                for index, target in enumerate(workspace.targets)
            ],
        })
        for index, target in enumerate(workspace.targets):
            await _terminal_send(websocket, send_lock, {
                "type": "status", "terminal": index, "status": "connecting",
                "message": f"Connecting to {target.label} ({target.ip})…"})

        async def connect_target(target):
            connection = ssh_manager.SSHSession(
                target.ip, target.ssh_username, target.password,
                target.switch_type, target.use_enable, target.enable_password,
                interactive=True)
            try:
                prompt = await asyncio.to_thread(connection.connect)
                return connection, prompt, None
            except ssh_manager.SSHError as exc:
                connection.disconnect()
                return None, "", str(exc)

        results = await asyncio.gather(
            *(connect_target(target) for target in workspace.targets))
        for index, ((connection, prompt, error), target) in enumerate(
                zip(results, workspace.targets)):
            if error:
                await _terminal_send(websocket, send_lock, {
                    "type": "status", "terminal": index, "status": "error",
                    "message": error})
                continue
            terminal_service.register_connection(workspace, connection)
            connections[index] = connection
            await _terminal_send(websocket, send_lock, {
                "type": "status", "terminal": index, "status": "connected",
                "message": ("Connected in enable mode." if target.use_enable
                            else "Connected.")})
            if prompt:
                await _terminal_send(websocket, send_lock, {
                    "type": "output", "terminal": index,
                    "data": f"\r\n{prompt}"})

        if not connections:
            await _terminal_send(websocket, send_lock, {
                "type": "ended", "message": "No SSH connection could be opened."})
            await websocket.close(code=1011)
            return

        receiver = asyncio.create_task(_terminal_input_loop(websocket, connections))
        pumps = {
            asyncio.create_task(_terminal_output_pump(
                websocket, send_lock, index, connection))
            for index, connection in connections.items()
        }
        while pumps:
            done, _ = await asyncio.wait(
                {receiver, *pumps}, return_when=asyncio.FIRST_COMPLETED)
            if receiver in done:
                try:
                    receiver.result()
                except (WebSocketDisconnect, RuntimeError):
                    pass
                break
            for task in done:
                if task is not receiver:
                    try:
                        task.result()
                    except (WebSocketDisconnect, RuntimeError):
                        pass
            pumps.difference_update(done)
        if not pumps and not receiver.done():
            await _terminal_send(websocket, send_lock, {
                "type": "ended", "message": "All SSH connections are closed."})
            await websocket.close(code=1000)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        log.warning("Interactive terminal failed: %s", exc)
        try:
            await _terminal_send(websocket, send_lock, {
                "type": "ended", "message": "The terminal session ended unexpectedly."})
        except Exception:
            pass
    finally:
        if receiver:
            receiver.cancel()
        for task in pumps:
            task.cancel()
        terminal_service.release(workspace)
        db = SessionLocal()
        try:
            audit.log_info(db, workspace.username, "Interactive terminal ended",
                           "SSH connections closed. Interactive commands were not recorded.")
        finally:
            db.close()


# ═══════════════════════ ANALYSIS ═══════════════════════

# Thread pool for parallelizing switch operations
_switch_executor = ThreadPoolExecutor(max_workers=10)

def _one_switch(t, fn):
    """One target, with the same per-switch error capture as _per_switch."""
    entry = {"switch_id": t.id, "switch_name": t.label,
             "switch_ip": t.ip, "switch_type": t.type,
             "is_nexus": t.is_nexus, "error": None}
    try:
        entry.update(fn(t) or {})
    except ssh_manager.SSHError as e:
        entry["error"] = str(e)
    except ValidationError as e:
        entry["error"] = str(e)
    return entry


def _per_switch(targets, fn):
    """Run fn(target) for each target in turn, capturing switch errors per switch.

    The sequential sibling of _per_switch_async, and not interchangeable with
    it. Callers whose own fn() already fans out across _switch_executor must
    use this one: _per_switch_async submits fn to that same pool, and a task
    waiting inside the pool for other tasks in the pool can deadlock it.
    """
    return [_one_switch(t, fn) for t in targets]


async def _per_switch_async(targets, fn):
    """Run fn(target) for each target in parallel, capturing switch errors per switch."""
    loop = asyncio.get_event_loop()
    
    async def process_target(t):
        entry = {"switch_id": t.id, "switch_name": t.label,
                 "switch_ip": t.ip, "switch_type": t.type,
                 "is_nexus": t.is_nexus, "error": None}
        try:
            # Run the blocking function in a thread pool
            result = await loop.run_in_executor(_switch_executor, fn, t)
            entry.update(result or {})
        except ssh_manager.SSHError as e:
            entry["error"] = str(e)
        except ValidationError as e:
            entry["error"] = str(e)
        except Exception as e:
            entry["error"] = str(e)
        return entry
    
    # Process all targets in parallel
    results = await asyncio.gather(*[process_target(t) for t in targets])
    return list(results)


def _check_access_on_target(t: svc.SwitchTarget, username: str, src: str,
                            dst: str, proto: str,
                            port: Optional[int],
                            icmp_type: Optional[str] = None) -> Dict[str, Any]:
    """Run the same complete route and ACL evaluation used by Access Checker."""
    src_r = acls.resolve_route(t, username, src) if src != "any" else \
                {"on_switch": False, "vlan": None, "raw": ""}
    dst_r = acls.resolve_route(t, username, dst) if dst != "any" else \
                {"on_switch": False, "vlan": None, "raw": ""}
    if not src_r["on_switch"] and not dst_r["on_switch"]:
        return {"on_this_switch": False,
                "note": "Neither address has its gateway on this switch, "
                        "so no ACL here applies to this traffic.",
                "src_route": src_r.get("raw", ""),
                "dst_route": dst_r.get("raw", "")}
    return {
        "on_this_switch": True,
        "source_side": (acls.evaluate_interface(t, username, src_r["vlan"],
                            src, dst, proto, port, "src", icmp_type)
                        if src_r["on_switch"] else
                        acls.side_not_on_switch("src",
                            "The source gateway is not on this switch.")),
        "destination_side": (acls.evaluate_interface(t, username, dst_r["vlan"],
                                 src, dst, proto, port, "dst", icmp_type)
                             if dst_r["on_switch"] else
                             acls.side_not_on_switch("dst",
                                 "The destination gateway is not on this switch.")),
    }


def _overall_access_verdict(results: List[Dict[str, Any]]) -> str:
    """One denied evaluated side makes the whole requested access denied."""
    for result in results:
        if result.get("error") or not result.get("on_this_switch"):
            continue
        for key in ("source_side", "destination_side"):
            if (result.get(key) or {}).get("verdict") == "DENIED":
                return "DENY"
    return "PERMIT"


@app.post("/api/acl/check")
async def check_access(data: sch.ACLCheckRequest,
                       cu: User = Depends(get_current_user),
                       db: Session = Depends(get_db)):
    src   = validate_ip_or_network(data.src_ip, "Source", allow_group=False)
    dst   = validate_ip_or_network(data.dst_ip, "Destination", allow_group=False)
    proto = validate_protocol(data.protocol)
    port  = validate_port_spec(data.port, proto)
    icmp_type = validate_icmp_type(data.icmp_type, proto)
    if src == "any" and dst == "any":
        raise ValidationError("Source and destination cannot both be 'any'.")
    port_int = acls.port_to_int(port)
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        return _check_access_on_target(
            t, cu.username, src, dst, proto, port_int, icmp_type)

    results = await _per_switch_async(targets, work)
    overall_verdict = _overall_access_verdict(results)
    audit.log_info(db, cu.username,
                   f"Checked access {src} → {dst} — {overall_verdict}",
                   f"Protocol {proto}" + (f", port {port}" if port else "") +
                   (f", ICMP type {icmp_type}" if icmp_type else "") +
                   f" · Result: {overall_verdict} · Switches: " +
                   ", ".join(t.label for t in targets))
    return {"src_ip": src, "dst_ip": dst, "protocol": proto, "port": port,
            "icmp_type": icmp_type,
            "verdict": overall_verdict, "switches": results}


@app.post("/api/acl/check-ip")
async def check_ip(data: sch.IPACLCheckRequest,
                   cu: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    ip = validate_ip_or_network(data.ip_address, "IP address",
                               allow_any=False, allow_group=False)
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        return _lookup_ip_policy_on_target(t, cu.username, ip)

    results = await _per_switch_async(targets, work)
    audit.log_info(db, cu.username, f"Looked up ACLs for {ip}",
                   "Switches: " + ", ".join(t.label for t in targets))
    return {"ip_address": ip, "switches": results}


def _lookup_ip_policy_on_target(t: svc.SwitchTarget, username: str,
                                ip: str) -> Dict[str, Any]:
    """Resolve an IP's gateway interface and the ACLs applied to it."""
    r = acls.resolve_route(t, username, ip)
    entry = {"on_switch": r["on_switch"],
             "interface": r.get("vlan") or r.get("interface"),
             "route_output": r.get("raw", ""), "acls": []}
    if r["on_switch"] and r.get("vlan"):
        for applied in svc.get_interface_acls(t, username, r["vlan"]):
            raw, lines = svc.get_acl_rules(t, username, applied["acl_name"])
            entry["acls"].append({"acl_name": applied["acl_name"],
                                  "direction": applied["direction"],
                                  "rule_count": len(lines),
                                  "rules": lines})
    return entry


@app.post("/api/acl/check-ip-global")
async def check_ip_global(data: sch.GlobalIPACLCheckRequest,
                          cu: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    """Look for an IP's gateway and applied ACLs across every owned switch."""
    ip = validate_ip(data.ip_address, "IP address")
    switches = db.query(Switch).filter(
        Switch.owner_username == cu.username).order_by(Switch.id).all()

    targets, setup_errors = [], []
    for switch in switches:
        try:
            targets.append(svc.resolve_targets(
                [switch.id], cu.username, db)[0])
        except HTTPException as exc:
            setup_errors.append({
                "switch_id": switch.id,
                "switch_name": switch.hostname or switch.ip_address,
                "switch_ip": switch.ip_address,
                "switch_type": (switch.switch_type or "ios").lower(),
                "is_nexus": (switch.switch_type or "ios").lower() == TYPE_NEXUS,
                "error": str(exc.detail), "on_switch": False,
                "interface": None, "route_output": "", "acls": [],
            })

    def work(target):
        return _lookup_ip_policy_on_target(target, cu.username, ip)

    results = await _per_switch_async(targets, work)
    by_id = {row["switch_id"]: row for row in results + setup_errors}
    ordered = [by_id[switch.id] for switch in switches if switch.id in by_id]
    gateway_switches = [row for row in ordered if row.get("on_switch")]
    acl_switches = [row for row in gateway_switches if row.get("acls")]
    audit.log_info(
        db, cu.username, f"Global IP ACL lookup for {ip}",
        f"Checked {len(switches)} switch{'es' if len(switches) != 1 else ''}; "
        f"gateway found on {len(gateway_switches)}, ACL applied on {len(acl_switches)}.")
    return {"ip_address": ip, "switches": ordered,
            "gateway_count": len(gateway_switches),
            "acl_switch_count": len(acl_switches)}


@app.post("/api/analysis/list-acls")
async def list_acls(data: sch.SwitchTargets, cu: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)
    results = await _per_switch_async(targets,
                          lambda t: {"acl_names": svc.list_acl_names(t, cu.username)})
    merged = sorted({n for r in results for n in r.get("acl_names", [])})
    return {"switches": results, "acl_names": merged}


@app.post("/api/analysis/view-acl")
async def view_acl(data: sch.AnalysisRequest, cu: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    name = validate_identifier(data.acl_name, "ACL name")
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        all_rules, all_kinds = svc.list_all_acls(t, cu.username)
        if name not in all_rules:
            return {"acls": [],
                    "note": f"No ACL named '{name}' exists on this switch."}
        lines = all_rules[name]
        applied = svc.map_acl_interfaces(t, cu.username).get(name, [])
        return {"acls": [{"acl_name": name, "total_rules": len(lines),
                          "rules": lines, "applied_on": applied,
                          "acl_kind": all_kinds.get(name, "extended")}]}

    return {"switches": await _per_switch_async(targets, work)}


@app.post("/api/analysis/view-all-acls")
async def view_all_acls(data: sch.SwitchTargets,
                        cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        all_rules, all_kinds = svc.list_all_acls(t, cu.username)
        applied_map = svc.map_acl_interfaces(t, cu.username)
        acl_list = [
            {"acl_name": n, "total_rules": len(lines),
             "rules": lines, "applied_on": applied_map.get(n, []),
             "acl_kind": all_kinds.get(n, "extended")}
            for n, lines in all_rules.items()
        ]
        return {"acls": acl_list}

    return {"switches": await _per_switch_async(targets, work)}


# The resolution logic itself lives in acl_parser so the fleet-health
# collector can reuse it without re-fetching. This name stays bound because
# test_nested_object_groups.py exercises it directly.
_expand_nested_group_members = acl_parser.expand_nested_group_members


def _object_group_members(t: svc.SwitchTarget, username: str):
    """Fetch every object group once and resolve their members into IP/port
    ranges, for group-aware coverage comparison."""
    return acl_parser.build_group_maps(svc.get_object_groups(t, username))


def _resolve_vpc_pair(switch_ids: List[int], username: str, db: Session,
                      require_write: bool = False
                      ) -> Tuple[svc.SwitchTarget, svc.SwitchTarget]:
    """Resolve exactly two switches that are Nexus AND actually paired as
    VPC peers with each other - stricter than resolve_targets, which only
    requires both-Nexus when two switches are selected."""
    targets = svc.resolve_targets(switch_ids, username, db,
                                  require_write=require_write)
    if len(targets) != 2:
        raise ValidationError("Select exactly two switches that are paired as VPC peers.")
    a, b = targets
    if a.sw.vpc_peer_id != b.id or b.sw.vpc_peer_id != a.id:
        raise ValidationError("These two switches aren't paired as VPC peers.")
    return a, b


@app.post("/api/analysis/redundant")
async def redundant(data: sch.AnalysisRequest,
                    cu: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    name = validate_identifier(data.acl_name, "ACL name")
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        _, lines = svc.get_acl_rules(t, cu.username, name)
        acl_kind = svc.get_acl_kind(t, cu.username, name)
        group_types, address_groups, service_groups = _object_group_members(t, cu.username)
        vlan_bindings, vlan_subnets = svc.get_vlan_acl_bindings_and_subnets(t, cu.username)
        time_ranges = svc.get_time_ranges(t, cu.username)
        return {"results": [{"acl_name": name, "total_rules": len(lines),
                             "acl_kind": acl_kind,
                             "redundancies": acl_parser.check_redundant_rules(
                                 lines, t.type, group_types, acl_kind,
                                 address_groups, service_groups),
                             "superseded_by_later": acl_parser.find_trailing_redundant_rules(
                                 lines, t.type, group_types, acl_kind,
                                 address_groups, service_groups),
                             "wrong_direction_rules": acl_parser.find_wrong_direction_rules(
                                 lines, vlan_bindings.get(name, []), vlan_subnets, t.type,
                                 group_types, acl_kind, address_groups),
                             "dead_schedule_rules": acl_parser.find_dead_schedule_rules(
                                 lines, time_ranges, t.type, group_types)}]}

    res = await _per_switch_async(targets, work)
    for t in targets:
        audit.log_info(db, cu.username, f"Redundancy check on ACL {name} on {t.label}",
                       "", switch_id=t.id)
    return {"switches": res}


@app.post("/api/analysis/redundant-all")
async def redundant_all(data: sch.SwitchTargets,
                        cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        group_types, address_groups, service_groups = _object_group_members(t, cu.username)
        all_rules, acl_kinds = svc.list_all_acls(t, cu.username)
        vlan_bindings, vlan_subnets = svc.get_vlan_acl_bindings_and_subnets(t, cu.username)
        # Read once for the whole switch rather than per ACL: expiry is a
        # property of the schedule, not of the list that references it.
        time_ranges = svc.get_time_ranges(t, cu.username)
        results = [
            {"acl_name": n, "total_rules": len(lines),
             "acl_kind": acl_kinds.get(n, "extended"),
             "redundancies": acl_parser.check_redundant_rules(
                 lines, t.type, group_types, acl_kinds.get(n, "extended"),
                 address_groups, service_groups),
             "superseded_by_later": acl_parser.find_trailing_redundant_rules(
                 lines, t.type, group_types, acl_kinds.get(n, "extended"),
                 address_groups, service_groups),
             "wrong_direction_rules": acl_parser.find_wrong_direction_rules(
                 lines, vlan_bindings.get(n, []), vlan_subnets, t.type,
                 group_types, acl_kinds.get(n, "extended"), address_groups),
             "dead_schedule_rules": acl_parser.find_dead_schedule_rules(
                 lines, time_ranges, t.type, group_types)}
            for n, lines in all_rules.items()
        ]
        return {"results": results}

    res = await _per_switch_async(targets, work)
    for t in targets:
        audit.log_info(db, cu.username, f"Redundancy check on all ACLs on {t.label}",
                       "", switch_id=t.id)
    return {"switches": res}


@app.post("/api/analysis/suggest-summary")
async def suggest_summary(data: sch.AnalysisRequest,
                          cu: User = Depends(get_current_user),
                          db: Session = Depends(get_db)):
    name = validate_identifier(data.acl_name, "ACL name")
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        _, lines = svc.get_acl_rules(t, cu.username, name)
        acl_kind = svc.get_acl_kind(t, cu.username, name)
        group_types = {g["name"]: g["kind"]
                       for g in svc.get_object_groups(t, cu.username)}
        return {"results": [{"acl_name": name, "total_rules": len(lines),
                             "suggestions": acl_parser.suggest_summary_rules(
                                 lines, t.type, group_types, acl_kind)}]}

    res = await _per_switch_async(targets, work)
    audit.log_info(db, cu.username, f"Summary suggestions for ACL {name}",
                   "Switches: " + ", ".join(t.label for t in targets))
    return {"switches": res}


@app.post("/api/analysis/suggest-summary-all")
async def suggest_summary_all(data: sch.SwitchTargets,
                              cu: User = Depends(get_current_user),
                              db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        group_types = {g["name"]: g["kind"]
                       for g in svc.get_object_groups(t, cu.username)}
        all_rules, acl_kinds = svc.list_all_acls(t, cu.username)
        results = [
            {"acl_name": n, "total_rules": len(lines),
             "suggestions": acl_parser.suggest_summary_rules(
                 lines, t.type, group_types, acl_kinds.get(n, "extended"))}
            for n, lines in all_rules.items()
        ]
        return {"results": results}

    res = await _per_switch_async(targets, work)
    audit.log_info(db, cu.username, "Summary suggestions for all ACLs",
                   "Switches: " + ", ".join(t.label for t in targets))
    return {"switches": res}


@app.post("/api/analysis/vpc-sync-check")
async def vpc_sync_check(data: sch.SwitchTargets,
                         cu: User = Depends(get_current_user),
                         db: Session = Depends(get_db)):
    switch_a, switch_b = _resolve_vpc_pair(data.switch_ids, cu.username, db)

    def vlan_only(mapping):
        return {name: [row for row in rows
                       if re.match(r"^vlan\d+$", row["interface"], re.IGNORECASE)]
               for name, rows in mapping.items()}

    (acls_a, _), (acls_b, _) = await asyncio.gather(
        asyncio.to_thread(svc.list_all_acls, switch_a, cu.username),
        asyncio.to_thread(svc.list_all_acls, switch_b, cu.username))
    acl_diffs = acl_parser.diff_acl_sets(acls_a, acls_b)

    map_a, map_b = await asyncio.gather(
        asyncio.to_thread(svc.map_acl_interfaces, switch_a, cu.username),
        asyncio.to_thread(svc.map_acl_interfaces, switch_b, cu.username))
    vlan_diffs = acl_parser.diff_vlan_acl_bindings(vlan_only(map_a), vlan_only(map_b))

    matching = sum(1 for d in acl_diffs if d["status"] == "match")
    audit.log_info(db, cu.username, f"VPC sync check on {switch_a.label}",
                   "", switch_id=switch_a.id)
    audit.log_info(db, cu.username, f"VPC sync check on {switch_b.label}",
                   "", switch_id=switch_b.id)
    return {
        "switch_a": {"id": switch_a.id, "label": switch_a.label, "site": switch_a.sw.site},
        "switch_b": {"id": switch_b.id, "label": switch_b.label, "site": switch_b.sw.site},
        "total_acls": len(acl_diffs), "matching_acls": matching,
        "acl_diffs": [d for d in acl_diffs if d["status"] != "match"],
        "vlan_diffs": vlan_diffs,
    }


@app.post("/api/analysis/object-groups")
async def object_groups(data: sch.ObjectGroupRequest,
                        cu: User = Depends(get_current_user),
                        db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        groups = svc.get_object_groups(t, cu.username)
        return {"groups": groups,
                "address_count": sum(1 for g in groups if g["kind"] == "address"),
                "port_count":    sum(1 for g in groups if g["kind"] == "port"),
                "note": None if groups else
                        "No object groups are configured on this switch."}

    return {"switches": await _per_switch_async(targets, work)}


@app.post("/api/analysis/time-ranges")
async def time_ranges(data: sch.TimeRangeListRequest,
                      cu: User = Depends(get_current_user),
                      db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def work(t):
        rs = svc.get_time_ranges(t, cu.username)
        return {"time_ranges": rs,
                "note": None if rs else
                        "No time-ranges are configured on this switch."}

    return {"switches": await _per_switch_async(targets, work)}


@app.post("/api/analysis/acl-report")
async def acl_report_endpoint(data: sch.AclReportRequest,
                              cu: User = Depends(get_current_user),
                              db: Session = Depends(get_db)):
    """Plain-language report describing what one ACL actually permits and
    denies, for a reader who cannot interpret ACL syntax. Read-only, so it
    is not admin-gated."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    _, rule_lines = await asyncio.to_thread(svc.get_acl_rules, t, cu.username, acl_name)
    if not rule_lines:
        raise ValidationError(
            f"'{acl_name}' has no rules on {t.label}, so there is nothing to report.")

    groups_list = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    time_ranges = await asyncio.to_thread(svc.get_time_ranges, t, cu.username)
    groups_by_name = {g["name"].lower(): g for g in groups_list}
    expanded = {g["name"]: _expand_nested_group_members(g["name"], groups_by_name)
                for g in groups_list}

    report = acl_report.build_acl_report(
        acl_name=acl_name, switch_label=t.label, switch_type=t.type,
        acl_kind=acl_kind, rule_lines=rule_lines, groups_list=groups_list,
        expanded_members=expanded, time_ranges=time_ranges)

    audit.log_info(db, cu.username, f"Generated an access report for '{acl_name}'",
                   f"Switch: {t.label}\n{report['summary']['total']} rule(s) described")
    return {
        "report": report,
        "markdown": acl_report.render_markdown(report),
        "html": acl_report.render_html(report),
    }


# ═══════════════════════ WRITE OPERATIONS ═══════════════════════

def _acl_ctx(acl_name: str, switch_type: str = "ios", kind: str = "extended") -> str:
    """Return the platform-specific ACL configuration context command."""
    if (switch_type or "ios").lower() in ("nexus", "nxos", "cisco_nxos"):
        return f"ip access-list {acl_name}"
    if (kind or "extended").lower() == "standard":
        return f"ip access-list standard {acl_name}"
    return f"ip access-list extended {acl_name}"


_GROUP_REF_RE = re.compile(r"\b(?:addrgroup|portgroup)\s+(\S+)", re.IGNORECASE)
_TIME_RANGE_REF_RE = re.compile(r"\btime-range\s+(\S+)", re.IGNORECASE)


def _acl_config_lines(raw_config: str, ctx: str) -> List[str]:
    """
    Extract an ACL's full config block (header + every rule/remark line,
    verbatim) from a 'show running-config | section <ctx>' response, for
    reconstructing the whole ACL on undo after a delete.
    """
    lines: List[str] = []
    started = False
    for raw in raw_config.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue
        if not started:
            if stripped.lower() == ctx.lower():
                lines.append(stripped)
                started = True
            continue
        if not raw[:1].isspace():
            break
        lines.append(f" {stripped}")
    return lines


def _acl_seq_map(lines: List[str]) -> Dict[int, str]:
    """Map sequence number -> full config line, from an _acl_config_lines()
    result (excluding its ctx header at index 0)."""
    out: Dict[int, str] = {}
    for line in lines[1:]:
        m = re.match(r"^\s*(\d+)\s+", line)
        if m:
            out[int(m.group(1))] = line
    return out


def _validate_rule_groups(t: svc.SwitchTarget, username: str,
                          src: str, dst: str, port: Optional[str],
                          protocol: str) -> Dict[str, Dict[str, Any]]:
    """Ensure every generic group input exists as the required platform type."""
    inventory = {g["name"].lower(): g
                 for g in svc.get_object_groups(t, username)}

    def require(value: Optional[str], keyword: str, kind: str, field: str):
        name = rule_generator.group_name(value, keyword)
        if not name:
            return None
        item = inventory.get(name.lower())
        if not item:
            raise ValidationError(
                f"{field} object group '{name}' does not exist on {t.label}.")
        if item["kind"] != kind:
            raise ValidationError(
                f"Object group '{name}' is a {item['kind']} group, not a "
                f"{kind} group required by {field.lower()}.")
        return item

    require(src, "addrgroup", "address", "Source")
    require(dst, "addrgroup", "address", "Destination")
    service = require(port, "portgroup", "port", "Port")

    if service and not t.is_nexus:
        members = acl_parser.parse_object_group_services(
            "\n".join(service["members"]))
        allowed_protocols = set()
        for member_protocol, _position, _op, _ports in members:
            if member_protocol == "tcp-udp":
                allowed_protocols.update(("tcp", "udp"))
            elif member_protocol:
                allowed_protocols.add(member_protocol)
        if protocol in ("tcp", "udp") and protocol not in allowed_protocols:
            raise ValidationError(
                f"IOS service object group '{service['name']}' has no "
                f"{protocol.upper()} members.")
    return inventory


def _representative_ips(value: str,
                        inventory: Dict[str, Dict[str, Any]]) -> List[str]:
    """Expand every address-group member into concrete route/access probes."""
    name = rule_generator.group_name(value, "addrgroup")
    if name:
        item = inventory[name.lower()]
        specs = acl_parser.parse_object_group_addresses(
            "\n".join(item["members"]))
    else:
        specs = [value]

    probes: List[str] = []
    for spec in specs:
        if spec == "any":
            continue
        if spec.startswith("range:"):
            start, end = spec.split(":", 1)[1].split("-", 1)
            first = int(ipaddress.IPv4Address(start))
            last = int(ipaddress.IPv4Address(end))
            if last - first + 1 + len(probes) > 512:
                raise ValidationError(
                    "The selected address group contains more than 512 IPs. "
                    "Split it into smaller groups so every IP can be checked.")
            probes.extend(str(ipaddress.IPv4Address(ip))
                          for ip in range(first, last + 1))
            continue
        net = ipaddress.IPv4Network(spec, strict=False)
        if net.num_addresses + len(probes) > 512:
            raise ValidationError(
                "The selected address group contains more than 512 IPs. "
                "Split it into smaller groups so every IP can be checked.")
        probes.extend(str(ip) for ip in net)

    unique = list(dict.fromkeys(probes))
    if len(unique) > 512:
        raise ValidationError(
            "The selected address group contains more than 512 IPs. Split it "
            "into smaller groups so every IP can be checked.")
    return unique


def _group_route_probes(value: str,
                        inventory: Dict[str, Dict[str, Any]]) -> List[str]:
    """Use one route-discovery IP per group member without expanding it."""
    name = rule_generator.group_name(value, "addrgroup")
    if not name:
        if value == "any":
            return []
        return [value.split("/")[0]]
    specs = acl_parser.parse_object_group_addresses(
        "\n".join(inventory[name.lower()]["members"]))
    probes = []
    for spec in specs:
        if spec == "any":
            continue
        if spec.startswith("range:"):
            probe = spec.split(":", 1)[1].split("-", 1)[0]
        else:
            network = ipaddress.IPv4Network(spec, strict=False)
            probe = str(network.network_address if network.num_addresses <= 2
                        else network.network_address + 1)
        if probe not in probes:
            probes.append(probe)
    if len(probes) > 512:
        raise ValidationError(
            "The selected address group has more than 512 members. Split it "
            "into smaller groups for route discovery.")
    return probes


def _port_probes(port: Optional[str], protocol: str,
                 inventory: Dict[str, Dict[str, Any]]) -> List[Optional[int]]:
    if not port:
        return [None]
    name = rule_generator.group_name(port, "portgroup")
    if not name:
        if "-" in port:
            lo, hi = (int(v) for v in port.split("-", 1))
            return [lo, hi]
        return [int(port)]

    conditions = acl_parser.parse_object_group_services(
        "\n".join(inventory[name.lower()]["members"]))
    probes: List[int] = []

    def add_ports(values):
        for value in values:
            if value not in probes:
                probes.append(value)
                if len(probes) > 10000:
                    raise ValidationError(
                        "The selected port group contains more than 10,000 "
                        "ports. Split it into smaller groups so every port "
                        "can be checked.")

    for member_proto, _position, op, ports in conditions:
        allowed = (("tcp", "udp") if member_proto == "tcp-udp"
                   else (member_proto,) if member_proto else ("tcp", "udp"))
        if protocol not in allowed:
            continue
        if not op:
            add_ports(range(1, 65536))
        elif op == "eq":
            add_ports(ports)
        elif op == "range":
            add_ports(range(ports[0], ports[1] + 1))
        elif op == "lt":
            add_ports(range(1, ports[0]))
        elif op == "gt":
            add_ports(range(ports[0] + 1, 65536))
        elif op == "neq":
            excluded = set(ports)
            add_ports(p for p in range(1, 65536) if p not in excluded)
    return probes or [None]


def _sequence_of(rule: Optional[str]) -> Optional[int]:
    match = re.match(r"^\s*(\d+)\s+", rule or "")
    return int(match.group(1)) if match else None


def _aggregate_policy_checks(check_records: List[Dict[str, Any]]) -> tuple:
    """Aggregate full Access Checker results by side, VLAN, ACL and direction."""
    policies: Dict[tuple, List[Dict[str, Any]]] = {}
    no_acl: Dict[tuple, bool] = {}
    for record in check_records:
        sample_src, sample_dst, sample_proto, sample_port = record["sample"]
        check = record["check"]
        for side in ("source", "destination"):
            result = check.get(f"{side}_side", {})
            vlan = result.get("vlan")
            if not vlan:
                continue
            if not result.get("acl_applied"):
                no_acl[(side, vlan)] = True
                continue
            for evaluated in result.get("evaluated_acls", []):
                key = (side, vlan, evaluated["acl_name"],
                       evaluated["direction"])
                policies.setdefault(key, []).append({
                    "verdict": evaluated["verdict"],
                    "matched_rule": evaluated.get("matched_rule"),
                    "src": sample_src, "dst": sample_dst,
                    "protocol": sample_proto, "port": sample_port,
                    "side": side, "vlan": vlan,
                    "acl_direction": evaluated["direction"],
                })
    return policies, no_acl


def _structural_acl_inspections(rule_lines: List[str], proposed_body: str,
                                switch_type: str,
                                group_types: Dict[str, str],
                                address_groups: Optional[Dict[str, List[str]]] = None,
                                service_groups: Optional[Dict[str, List[tuple]]] = None
                                ) -> List[Dict[str, Any]]:
    """Find the first unconditional ACL rule that fully covers a proposed rule."""
    proposed = acl_parser.parse_acl_rule(
        proposed_body, switch_type, group_types)
    if not proposed:
        raise ValidationError(
            "The generated object-group rule could not be parsed safely.")
    address_groups = address_groups or {}
    service_groups = service_groups or {}

    def covers(broader, narrower):
        return (acl_parser.rule_covers(
                    broader, narrower, require_same_action=False) or
                acl_parser.rule_covers_with_group_members(
                    broader, narrower, address_groups, service_groups,
                    require_same_action=False))

    for raw in rule_lines:
        existing = acl_parser.parse_acl_rule(raw, switch_type, group_types)
        if not existing:
            continue
        if covers(existing, proposed):
            return [{
                "verdict": ("PERMITTED" if existing["action"] == "permit"
                            else "DENIED"),
                "matched_rule": raw,
            }]
        if existing["action"] == "deny" and covers(proposed, existing):
            return [{"verdict": "DENIED", "matched_rule": raw}]
    return [{"verdict": "DENIED", "matched_rule": None}]


def _select_rule_sequence(rule_lines: List[str], inspections: List[Dict[str, Any]],
                          requested: Optional[int]) -> tuple:
    """Choose an unused sequence strictly below the effective denying rule."""
    denying = [r for r in inspections
               if r["verdict"] == "DENIED" and r.get("matched_rule")]
    blocking_rule = min(
        (r["matched_rule"] for r in denying),
        key=lambda line: _sequence_of(line) or 4294967295,
        default=None)
    blocking_seq = _sequence_of(blocking_rule)
    used = {_sequence_of(line) for line in rule_lines}
    used.discard(None)

    if requested is not None:
        if requested in used:
            raise ValidationError(
                f"Sequence {requested} already exists in this ACL. Choose an "
                "unused sequence number.")
        if blocking_seq is not None and requested >= blocking_seq:
            raise ValidationError(
                f"Sequence {requested} would be at or below denying rule "
                f"{blocking_seq}. Choose a sequence below {blocking_seq}.")
        return requested, blocking_rule

    if blocking_seq is None:
        candidate = 10
        while candidate in used and candidate <= 4294967294:
            candidate += 10
        if candidate > 4294967294:
            raise ValidationError("No unused ACL sequence number is available.")
        return candidate, None

    # Prefer conventional increments of ten, always starting at 10.
    for candidate in range(10, blocking_seq, 10):
        if candidate not in used:
            return candidate, blocking_rule

    # If every usable multiple of ten is occupied (or the deny is below 10),
    # fall back to the first free integer, still strictly before the deny.
    for candidate in range(1, blocking_seq):
        if candidate not in used:
            return candidate, blocking_rule
    raise ValidationError(
        f"Denying rule {blocking_seq} blocks this access, but there is no "
        f"unused sequence number lower than {blocking_seq}. Resequence the ACL.")


def _select_rule_and_remark_sequence(
        rule_lines: List[str], inspections: List[Dict[str, Any]],
        requested: Optional[int], wants_remark: bool,
        occupied_sequences: Optional[set] = None,
        requested_remark: Optional[int] = None) -> tuple:
    """Choose the normal rule sequence, preferring a free preceding remark slot."""
    if not wants_remark:
        rule_sequence, blocking_rule = _select_rule_sequence(
            rule_lines, inspections, requested)
        return rule_sequence, None, blocking_rule
    occupied = set(occupied_sequences or ())
    occupied.update(seq for seq in (_sequence_of(line) for line in rule_lines)
                    if seq is not None)
    selection_lines = list(rule_lines) + [
        f"{seq} remark occupied" for seq in occupied
        if not any(_sequence_of(line) == seq for line in rule_lines)
    ]
    first_rule, blocking_rule = _select_rule_sequence(
        selection_lines, inspections, requested)
    def has_remark_slot(candidate: int) -> bool:
        return candidate > 1 and candidate - 1 not in occupied

    blocking_seq = _sequence_of(blocking_rule)
    seen = set()

    def candidates():
        if blocking_seq is None:
            candidate = 10
            while candidate <= 4294967294:
                yield candidate
                candidate += 10
            return
        yield from range(10, blocking_seq, 10)
        yield from range(1, blocking_seq)

    if requested_remark is not None:
        rule_sequences = {_sequence_of(line) for line in rule_lines}
        rule_sequences.discard(None)
        if requested_remark in rule_sequences:
            raise ValidationError(
                f"Remark sequence {requested_remark} is occupied by an ACL "
                "rule. Choose an unused sequence number.")
        if requested is not None:
            if requested_remark >= first_rule:
                raise ValidationError(
                    f"Remark sequence {requested_remark} must be lower than "
                    f"rule sequence {first_rule}.")
            return first_rule, requested_remark, blocking_rule
        immediate_rule = requested_remark + 1
        if (immediate_rule <= 4294967294 and
                (blocking_seq is None or immediate_rule < blocking_seq) and
                immediate_rule not in occupied):
            return immediate_rule, requested_remark, blocking_rule
        if requested_remark < first_rule:
            return first_rule, requested_remark, blocking_rule
        first_multiple = max(10, ((requested_remark // 10) + 1) * 10)
        upper_bound = blocking_seq if blocking_seq is not None else 4294967295
        for candidate in range(first_multiple, upper_bound, 10):
            if candidate not in occupied:
                return candidate, requested_remark, blocking_rule
        if blocking_seq is not None:
            for candidate in range(max(1, requested_remark + 1), blocking_seq):
                if candidate not in occupied:
                    return candidate, requested_remark, blocking_rule
        raise ValidationError(
            f"No unused rule sequence higher than remark sequence "
            f"{requested_remark} is available before the effective deny.")

    if requested is not None:
        if has_remark_slot(first_rule):
            return first_rule, first_rule - 1, blocking_rule
        return first_rule, None, blocking_rule
    if has_remark_slot(first_rule):
        return first_rule, first_rule - 1, blocking_rule

    for candidate in candidates():
        if candidate in seen:
            continue
        seen.add(candidate)
        if candidate in occupied:
            continue
        if has_remark_slot(candidate):
            return candidate, candidate - 1, blocking_rule

    # Preserve the sequence the original algorithm would have selected. The
    # caller will warn and omit the remark rather than blocking the rule.
    return first_rule, None, blocking_rule


def _canonical_acl_rule(rule: str) -> str:
    # Strip trailing display-only annotations Cisco appends to `show`
    # output — match counts and state markers like "(56 matches)" or
    # "(inactive)" on IOS, "[match=56]" on NX-OS — that aren't part of the
    # actual rule syntax.
    value = re.sub(r"(?:\s+\([^)]*\)|\s+\[match=\d+\])+\s*$", "", rule.strip(),
                   flags=re.IGNORECASE)
    # NX-OS commonly echoes `host A.B.C.D` as `A.B.C.D/32`. They are the
    # same ACL operand and must compare equal during post-apply verification.
    value = re.sub(
        r"\bhost\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
        lambda match: f"{match.group(1)}/32",
        value,
        flags=re.IGNORECASE,
    )
    return " ".join(value.split()).lower()


def _rule_was_applied(rule_lines: List[str], expected: str) -> bool:
    canonical = _canonical_acl_rule(expected)
    return any(_canonical_acl_rule(line) == canonical for line in rule_lines)


def _find_acl_remark(output: str, sequence: int) -> Optional[str]:
    pattern = re.compile(
        rf"^\s*{sequence}\s+remark(?:\s+.*)?$", re.IGNORECASE)
    return next((line.strip() for line in output.splitlines()
                 if pattern.match(line)), None)


def _acl_sequence_numbers(output: str) -> set:
    return {int(match.group(1)) for match in re.finditer(
        r"^\s*(\d+)\s+(?:permit|deny|remark)\b", output,
        re.IGNORECASE | re.MULTILINE)}


def _canonical_acl_remark(value: str) -> str:
    return " ".join(value.split()).lower()


def _remark_was_applied(output: str, expected: str) -> bool:
    canonical = _canonical_acl_remark(expected)
    return any(_canonical_acl_remark(line) == canonical
               for line in output.splitlines())


def _acl_remark_output(t: svc.SwitchTarget, username: str,
                       acl_name: str) -> str:
    """Read remarks from the command that exposes them on each platform."""
    if not t.is_nexus:
        return svc.show(
            t, username,
            f"show running-config | section ip access-list extended {acl_name}",
            timeout=30)
    output, _ = svc.get_acl_rules(t, username, acl_name)
    return output


@app.post("/api/write/rule-preview")
async def rule_preview(data: sch.RulePreviewRequest,
                       cu: User = Depends(require_admin),
                       db: Session = Depends(get_db)):
    src   = validate_ip_or_network(data.src_ip, "Source")
    dst   = validate_ip_or_network(data.dst_ip, "Destination")
    proto = validate_protocol(data.protocol)
    port  = validate_port_spec(data.port, proto)
    icmp_type = validate_icmp_type(data.icmp_type, proto)
    established = validate_established(data.established, proto, port)
    time_range = (validate_identifier(data.time_range, "Time range")
                  if data.time_range else None)
    remark = validate_remark(data.remark)
    remark_requested_seq = validate_sequence(data.remark_sequence_number)
    if remark_requested_seq is not None and not remark:
        raise ValidationError(
            "Enter remark text before setting a remark sequence.")
    seq   = validate_sequence(data.sequence_number)
    if src == "any" and dst == "any":
        raise ValidationError("Source and destination cannot both be 'any'.")

    targets  = svc.resolve_targets(data.switch_ids, cu.username, db, require_write=True)

    def work(t):
        target_time_range = None
        if time_range:
            configured_ranges = svc.get_time_ranges(t, cu.username)
            configured = next(
                (item for item in configured_ranges
                 if item["name"].lower() == time_range.lower()), None)
            if not configured:
                raise ValidationError(
                    f"Time range '{time_range}' does not exist on {t.label}.")
            target_time_range = configured["name"]

        inventory = _validate_rule_groups(
            t, cu.username, src, dst, port, proto)
        uses_groups = any((
            rule_generator.group_name(src, "addrgroup"),
            rule_generator.group_name(dst, "addrgroup"),
            rule_generator.group_name(port, "portgroup"),
        ))
        if uses_groups:
            src_probes = _group_route_probes(src, inventory)
            dst_probes = _group_route_probes(dst, inventory)
        else:
            src_probes = (_representative_ips(src, inventory)
                          if src != "any" else ["any"])
            dst_probes = (_representative_ips(dst, inventory)
                          if dst != "any" else ["any"])

        if uses_groups:
            # Object-group mode avoids the expensive Cartesian Access Checker
            # scan. Resolve each address once only to discover relevant VLANs,
            # then compare the complete generated group rule structurally with
            # the ordered rules on each ACL.
            route_inputs = ([('source', ip) for ip in src_probes if ip != "any"] +
                            [('destination', ip) for ip in dst_probes if ip != "any"])

            def resolve_tagged(item):
                side, ip = item
                return side, ip, acls.resolve_route(t, cu.username, ip)

            route_records = list(_switch_executor.map(
                resolve_tagged, route_inputs))
            side_vlans = []
            for side, _ip, route in route_records:
                if route["on_switch"] and route.get("vlan"):
                    pair = (side, route["vlan"])
                    if pair not in side_vlans:
                        side_vlans.append(pair)

            policies: Dict[tuple, List[Dict[str, Any]]] = {}
            no_acl: Dict[tuple, bool] = {}
            group_types = {name: item["kind"]
                           for name, item in inventory.items()}
            address_groups = {
                item["name"]: acl_parser.parse_object_group_addresses(
                    "\n".join(item["members"]))
                for item in inventory.values() if item["kind"] == "address"
            }
            service_groups = {
                item["name"]: acl_parser.parse_object_group_services(
                    "\n".join(item["members"]))
                for item in inventory.values() if item["kind"] == "port"
            }
            for side, vlan in side_vlans:
                applications = svc.get_interface_acls(t, cu.username, vlan)
                if not applications:
                    no_acl[(side, vlan)] = True
                    continue
                vlan_side = "src" if side == "source" else "dst"
                for application in applications:
                    acl_name = application["acl_name"]
                    direction = application["direction"]
                    body, _ = rule_generator.generate_permit_rule(
                        src_ip=src, dst_ip=dst, proto=proto, port=port,
                        acl_direction=direction, vlan_ip_side=vlan_side,
                        switch_type=t.type, time_range=target_time_range,
                        icmp_type=icmp_type, established=established)
                    _, rule_lines = svc.get_acl_rules(
                        t, cu.username, acl_name)
                    inspections = _structural_acl_inspections(
                        rule_lines, body, t.type, group_types,
                        address_groups, service_groups)
                    for inspection in inspections:
                        inspection.update({
                            "side": side, "vlan": vlan,
                            "acl_direction": direction,
                        })
                    policies[(side, vlan, acl_name, direction)] = inspections
        else:
            ports = _port_probes(port, proto, inventory)
            traffic_samples = [
                (sample_src, sample_dst, proto, sample_port)
                for sample_src in src_probes
                for sample_dst in dst_probes
                for sample_port in ports
            ]
            if len(traffic_samples) > 10000:
                raise ValidationError(
                    "The selected inputs produce more than 10,000 access "
                    "combinations. Split the request into smaller previews.")

            def check_sample(sample):
                sample_src, sample_dst, sample_proto, sample_port = sample
                return {
                    "sample": sample,
                    "check": _check_access_on_target(
                        t, cu.username, sample_src, sample_dst,
                        sample_proto, sample_port, icmp_type),
                }

            check_records = list(_switch_executor.map(
                check_sample, traffic_samples))
            policies, no_acl = _aggregate_policy_checks(check_records)
            if target_time_range:
                # Access Checker discovers the relevant interfaces. Compare
                # the timed rule structurally afterward so a permit tied to a
                # different schedule cannot hide an effective deny.
                for policy_key in list(policies):
                    side, vlan, acl_name, direction = policy_key
                    vlan_side = "src" if side == "source" else "dst"
                    body, _ = rule_generator.generate_permit_rule(
                        src_ip=src, dst_ip=dst, proto=proto, port=port,
                        acl_direction=direction, vlan_ip_side=vlan_side,
                        switch_type=t.type, time_range=target_time_range,
                        icmp_type=icmp_type, established=established)
                    _, rule_lines = svc.get_acl_rules(
                        t, cu.username, acl_name)
                    inspections = _structural_acl_inspections(
                        rule_lines, body, t.type, {})
                    for inspection in inspections:
                        inspection.update({
                            "side": side, "vlan": vlan,
                            "acl_direction": direction,
                        })
                    policies[policy_key] = inspections
        if not policies and not no_acl:
            return {"previews": [], "existing_access": {},
                    "note": "None of the supplied addresses or address-group "
                            "members has its gateway on this switch, so there "
                            "is no interface here to attach a rule to."}

        # Build the full object-group rule for every affected policy, then
        # merge identical rules targeting the same ACL.
        candidates: Dict[tuple, Dict[str, Any]] = {}
        for (side, vlan, acl_name, direction), inspections in policies.items():
            vlan_side = "src" if side == "source" else "dst"
            body, explanation = rule_generator.generate_permit_rule(
                src_ip=src, dst_ip=dst, proto=proto, port=port,
                acl_direction=direction, vlan_ip_side=vlan_side,
                switch_type=t.type, time_range=target_time_range,
                icmp_type=icmp_type, established=established)
            key = (acl_name, body)
            candidate = candidates.setdefault(key, {
                "acl_name": acl_name, "body": body,
                "explanation": explanation, "sides": [], "vlans": [],
                "directions": [], "inspections": [],
            })
            if side not in candidate["sides"]:
                candidate["sides"].append(side)
            if vlan not in candidate["vlans"]:
                candidate["vlans"].append(vlan)
            if direction not in candidate["directions"]:
                candidate["directions"].append(direction)
            candidate["inspections"].extend(inspections)

        existing: Dict[str, Any] = {}
        previews: List[Dict[str, Any]] = [{
            "side": side, "vlan": vlan,
            "warning": f"No ACL is applied to {vlan} on this switch, so "
                       f"access is already permitted on the {side} side. "
                       f"There is nothing to add."
        } for side, vlan in no_acl]
        reserved_lines: Dict[str, List[str]] = {}
        reserved_sequences: Dict[str, set] = {}
        acl_outputs: Dict[str, str] = {}

        for candidate in candidates.values():
            acl_name = candidate["acl_name"]
            inspections = candidate["inspections"]
            if acl_name not in reserved_lines:
                acl_output, rule_lines = svc.get_acl_rules(
                    t, cu.username, acl_name)
                remark_output = (_acl_remark_output(t, cu.username, acl_name)
                                 if remark else acl_output)
                acl_outputs[acl_name] = remark_output
                reserved_lines[acl_name] = list(rule_lines)
                reserved_sequences[acl_name] = (
                    _acl_sequence_numbers(acl_output) |
                    _acl_sequence_numbers(remark_output))
            if remark:
                next_seq, remark_seq, blocking_rule = _select_rule_and_remark_sequence(
                    reserved_lines[acl_name], inspections, seq, True,
                    reserved_sequences[acl_name], remark_requested_seq)
            else:
                # Preserve the original auto-sequence behavior exactly when
                # no remark was requested.
                next_seq, blocking_rule = _select_rule_sequence(
                    reserved_lines[acl_name], inspections, seq)
                remark_seq = None
            rule_line = f"{next_seq} {candidate['body']}"
            remark_line = (f"{remark_seq} remark {remark}"
                           if remark and remark_seq is not None else None)
            replaced_remark = (_find_acl_remark(
                acl_outputs[acl_name], remark_seq) if remark_line else None)
            remark_commands = []
            if (replaced_remark and
                    _canonical_acl_remark(replaced_remark) !=
                    _canonical_acl_remark(remark_line)):
                remark_commands.append(f"no {remark_seq} remark")
            if remark_line:
                remark_commands.append(remark_line)
            reserved_lines[acl_name].append(rule_line)
            reserved_sequences[acl_name].add(next_seq)
            if remark_seq is not None:
                reserved_sequences[acl_name].add(remark_seq)

            permitted = []
            seen_permits = set()
            for inspection in inspections:
                matched = inspection.get("matched_rule")
                if inspection["verdict"] != "PERMITTED" or not matched:
                    continue
                permit_key = matched
                if permit_key in seen_permits:
                    continue
                seen_permits.add(permit_key)
                permitted.append(inspection)
            all_permitted = bool(inspections) and all(
                r["verdict"] == "PERMITTED" for r in inspections)
            side_label = " and ".join(candidate["sides"])
            vlan_label = ", ".join(candidate["vlans"])
            direction_label = " and ".join(candidate["directions"])
            existing_entries = [{
                "acl_name": acl_name,
                "acl_direction": item["acl_direction"],
                "matched_rule": item["matched_rule"],
                "vlan": item["vlan"],
            } for item in permitted]
            if existing_entries:
                existing[f"{side_label}:{vlan_label}:{acl_name}"] = existing_entries

            previews.append({
                "side": side_label, "vlan": vlan_label,
                "acl_name": acl_name, "acl_direction": direction_label,
                "acl_directions": candidate["directions"],
                "sequence_number": next_seq, "rule_syntax": rule_line,
                "remark": remark, "remark_syntax": remark_line,
                "remark_sequence": remark_seq,
                "remark_warning": (
                    "No empty sequence was found for the remark immediately "
                    "before the selected rule sequence. The permit rule will "
                    "be applied without a remark."
                    if remark and remark_seq is None else None),
                "replaced_remark": replaced_remark,
                "explanation": candidate["explanation"],
                "already_permitted": all_permitted,
                "partially_permitted": bool(existing_entries) and not all_permitted,
                "existing_access": (existing_entries[0]
                                    if existing_entries else None),
                "existing_accesses": existing_entries,
                "blocking_rule": blocking_rule,
                "sequence_reason": (
                    f"Placed before denying rule {_sequence_of(blocking_rule)}."
                    if blocking_rule else
                    "No explicit matching deny was found; placed at the end "
                    "before the implicit deny."),
                "cli_commands": ([_acl_ctx(acl_name, t.type), f" {rule_line}"]
                                 + [f" {command}" for command in remark_commands]
                                 + ["exit"]),
                "acl_context": _acl_ctx(acl_name, t.type),
            })

        return {"previews": previews, "existing_access": existing}

    # work() parallelizes internally via _switch_executor.map(); running the
    # outer per-target loop through asyncio's default thread pool (rather
    # than _switch_executor itself) avoids event-loop blocking without
    # risking pool-reentrancy deadlock between the outer and inner calls.
    # One switch per thread from asyncio's own pool, so a VPC pair is previewed
    # in the time of one rather than two. Deliberately not _per_switch_async:
    # work() already fans out across _switch_executor, and submitting it to that
    # same pool risks a task waiting inside the pool for other tasks in it.
    #
    # cached_reads() collapses the repeated `show` commands one preview issues
    # -- the same time-range fetched three times, the ACL and the object-group
    # table twice each. Safe here because a preview only reads.
    with svc.cached_reads(targets):
        switches = list(await asyncio.gather(
            *[asyncio.to_thread(_one_switch, t, work) for t in targets]))
    return {"switches": switches,
            "src_ip": src, "dst_ip": dst, "protocol": proto, "port": port,
            "time_range": time_range, "remark": remark}


@app.post("/api/write/rule-check-existing")
async def rule_check_existing(data: sch.RuleCheckExistingRequest,
                              cu: User = Depends(require_admin),
                              db: Session = Depends(get_db)):
    """
    Structurally compare a manually-typed rule against an ACL's current
    rules and report whether the requested access is already permitted —
    the same check the Add Rule page runs via rule-preview, reused here for
    View ACL's manual add-rule form. Standard IOS ACLs are skipped: their
    rules have no destination/port, so the extended-rule structural
    comparison doesn't apply.
    """
    acl_name = validate_identifier(data.acl_name, "ACL name")
    rule = validate_acl_rule_line(data.rule_syntax)
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    def _do():
        _, rule_lines = svc.get_acl_rules(t, cu.username, acl_name)
        if svc.get_acl_kind(t, cu.username, acl_name) == "standard":
            return {"already_permitted": False, "matched_rule": None}

        seq_m = re.match(r"^\d+\s+(.*)$", rule)
        body = seq_m.group(1) if seq_m else rule

        inventory = {g["name"].lower(): g for g in svc.get_object_groups(t, cu.username)}
        group_types = {item["name"]: item["kind"] for item in inventory.values()}
        address_groups = {
            item["name"]: acl_parser.parse_object_group_addresses("\n".join(item["members"]))
            for item in inventory.values() if item["kind"] == "address"
        }
        service_groups = {
            item["name"]: acl_parser.parse_object_group_services("\n".join(item["members"]))
            for item in inventory.values() if item["kind"] == "port"
        }
        inspections = _structural_acl_inspections(
            rule_lines, body, t.type, group_types, address_groups, service_groups)
        permitted = next((i for i in inspections
                          if i["verdict"] == "PERMITTED" and i.get("matched_rule")), None)
        return {
            "already_permitted": bool(permitted),
            "matched_rule": permitted["matched_rule"] if permitted else None,
        }

    return await asyncio.to_thread(_do)


@app.post("/api/write/rule-apply")
async def rule_apply(data: sch.RuleApplyRequest,
                     cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    rule     = validate_acl_rule_line(data.rule_syntax)
    remark   = validate_remark(data.remark)
    remark_seq = (validate_sequence(data.remark_sequence)
                  if remark else None)
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t        = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    seq_m = re.match(r"^(\d+)\s", rule)
    if not seq_m:
        raise ValidationError(
            "A sequence number is required so the rule can be placed and "
            "verified safely. Generate a new preview or add a sequence.")
    rule_seq = int(seq_m.group(1))
    if remark and remark_seq is None:
        raise ValidationError(
            "A remark sequence is required. Generate a fresh preview.")
    if remark_seq is not None and remark_seq >= rule_seq:
        raise ValidationError(
            "The remark sequence must be lower than the rule sequence.")
    # Every SSH round trip below runs via asyncio.to_thread so a slow switch
    # doesn't stall the event loop (and with it every other request and open
    # terminal session). Audit/DB writes stay on this thread — SQLAlchemy
    # sessions (and SQLite in particular) aren't safe to touch from a worker
    # thread other than the one that created them.
    acl_show_out, before_lines = await asyncio.to_thread(
        svc.get_acl_rules, t, cu.username, acl_name)
    before_out = (await asyncio.to_thread(_acl_remark_output, t, cu.username, acl_name)
                  if remark else acl_show_out)
    collision = next((line for line in before_lines
                      if _sequence_of(line) == rule_seq), None)
    if collision:
        return {
            "success": False,
            "message": (f"Sequence {rule_seq} already exists in {acl_name}. "
                        "Generate a fresh preview; no command was sent."),
            "output": "",
            "undo_commands": [],
        }
    remark_collision = (next((line for line in before_lines
                              if _sequence_of(line) == remark_seq), None)
                        if remark_seq is not None else None)
    if remark_collision:
        return {
            "success": False,
            "message": (f"Remark sequence {remark_seq} is now occupied by an "
                        f"ACL rule in {acl_name}. Generate a fresh preview; "
                        "no command was sent."),
            "output": "", "undo_commands": [],
        }

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    acl_context = _acl_ctx(acl_name, t.type, acl_kind)
    remark_line = f"{remark_seq} remark {remark}" if remark else None
    previous_remark = (_find_acl_remark(before_out, remark_seq)
                       if remark_seq is not None else None)

    def rollback_sequence() -> str:
        rollback = [acl_context, f"no {rule_seq}"]
        if remark_seq is not None:
            rollback.append(f"no {remark_seq}")
        if previous_remark:
            rollback.append(previous_remark)
        _ok, rollback_out, _err = svc.configure(
            t, cu.username, rollback)
        return rollback_out

    # The permit is always installed and verified first. A failed permit must
    # never create or replace a remark.
    cmds = [acl_context, rule]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds)
    undo = [acl_context, f"no {rule_seq}"]
    if remark_seq is not None:
        undo.append(f"no {remark_seq}")
    if previous_remark:
        undo.append(previous_remark)

    if not ok:
        rollback_out = await asyncio.to_thread(rollback_sequence)
        audit.log_error(db, cu.username,
                        f"Failed to add a rule to {acl_name} on {t.label}",
                        f"Rule: {rule}\nProblem: {err}\n\nSwitch output:\n{out}"
                        + (f"\n\nRollback output:\n{rollback_out}" if rollback_out else ""),
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False, "message": err or "The switch rejected the rule.",
                "output": out + (f"\n\nRollback response:\n{rollback_out}"
                                 if rollback_out else ""), "undo_commands": []}

    try:
        verify_out, verify_lines = await asyncio.to_thread(
            svc.get_acl_rules, t, cu.username, acl_name)
    except ssh_manager.SSHError as exc:
        verify_out, verify_lines = str(exc), []
    if not _rule_was_applied(verify_lines, rule):
        rollback_out = await asyncio.to_thread(rollback_sequence)
        message = ("The switch did not confirm the requested rule in the ACL. "
                   "The rule was rolled back and no remark was created; review "
                   "the raw switch output below.")
        combined = (f"Configuration response:\n{out}\n\n"
                    f"Verification response:\n{verify_out}\n\n"
                    f"Rollback response:\n{rollback_out}")
        audit.log_error(db, cu.username,
                        f"Could not verify rule in {acl_name} on {t.label}",
                        f"Rule: {rule}\n{combined}")
        return {"success": False, "message": message, "output": combined,
                "undo_commands": []}

    # Only a confirmed permit is allowed to create or replace its remark.
    remark_out = ""
    remark_verify_out = verify_out
    if remark_line:
        remark_commands = [acl_context]
        if (previous_remark and
                _canonical_acl_remark(previous_remark) !=
                _canonical_acl_remark(remark_line)):
            remark_commands.append(f"no {remark_seq} remark")
        remark_commands.append(remark_line)
        remark_ok, remark_out, remark_err = await asyncio.to_thread(
            svc.configure, t, cu.username, remark_commands)
        if not remark_ok:
            rollback_out = await asyncio.to_thread(rollback_sequence)
            message = ("The permit rule was applied, but the switch rejected "
                       "its ACL remark. The rule was rolled back. The switch "
                       "may not support sequenced remarks, or the remark syntax "
                       f"was invalid. {remark_err or ''}").strip()
            combined = (f"Rule configuration response:\n{out}\n\n"
                        f"Remark configuration response:\n{remark_out}\n\n"
                        f"Rollback response:\n{rollback_out}")
            audit.log_error(
                db, cu.username,
                f"Failed to add an ACL remark to {acl_name} on {t.label}",
                f"Rule: {rule}\nRemark: {remark_line}\nProblem: {remark_err}\n"
                f"{combined}",
                            event_type=db_models.EV_WRITE_FAILED)
            return {"success": False, "message": message,
                    "output": combined, "undo_commands": []}
        try:
            remark_verify_out = await asyncio.to_thread(
                _acl_remark_output, t, cu.username, acl_name)
            _rule_verify_out, remark_verify_lines = await asyncio.to_thread(
                svc.get_acl_rules, t, cu.username, acl_name)
        except ssh_manager.SSHError as exc:
            remark_verify_out, remark_verify_lines = str(exc), []
        remark_confirmed = _remark_was_applied(remark_verify_out, remark_line)
        rule_still_present = _rule_was_applied(remark_verify_lines, rule)
        if not remark_confirmed or not rule_still_present:
            rollback_out = await asyncio.to_thread(rollback_sequence)
            combined = (f"Rule configuration response:\n{out}\n\n"
                        f"Remark configuration response:\n{remark_out}\n\n"
                        f"Remark verification response:\n{remark_verify_out}\n\n"
                        f"Rollback response:\n{rollback_out}")
            message = ("The switch did not retain both the permit rule and its "
                       "ACL remark. The change was rolled "
                       "back. This switch may not support sequenced ACL remarks.")
            audit.log_error(
                db, cu.username,
                f"Could not verify ACL remark in {acl_name} on {t.label}",
                f"Rule: {rule}\nRemark: {remark_line}\n{combined}")
            return {"success": False, "message": message,
                    "output": combined, "undo_commands": []}
    undo_label = (f"remove rule {rule_seq} and remark {remark_seq} from {acl_name}"
                  if remark_seq is not None else
                  f"remove rule {rule_seq} from {acl_name}")
    audit.log_success(db, cu.username,
                      f"Added a rule to {acl_name} on {t.label}",
                      f"Rule: {rule}"
                      + (f"\nRemark: {remark_line}" if remark_line else "")
                      + f"\nCommands: {' ; '.join(([acl_context, rule]
                          + ([f'no {remark_seq} remark'] if previous_remark and remark_line and _canonical_acl_remark(previous_remark) != _canonical_acl_remark(remark_line) else [])
                          + ([remark_line] if remark_line else [])))}",
                      undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_RULE_ADD)
    return {"success": True,
            "message": f"Rule added to {acl_name} on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": (out + (f"\n\nRemark response:\n{remark_out}"
                              if remark_out else "")),
            "verification_output": remark_verify_out,
            "undo_commands": undo,
            "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/rule-delete")
async def rule_delete(data: sch.RuleDeleteRequest,
                      cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    seq      = validate_sequence(data.sequence_number)
    if seq is None:
        raise ValidationError("A sequence number is required to delete a rule.")
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    # Capture the original line so the deletion can be undone
    _, lines = await asyncio.to_thread(svc.get_acl_rules, t, cu.username, acl_name)
    original = next((l for l in lines if re.match(rf"^{seq}\s", l.strip())), None)
    if original is None:
        raise ValidationError(
            f"Rule {seq} was not found in {acl_name}. It may already be gone — "
            f"refresh the ACL view.")

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    cmds = [_acl_ctx(acl_name, t.type, acl_kind), f"no {seq}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to delete rule {seq} from {acl_name} on {t.label}",
                        f"Problem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False, "message": err or "The switch rejected the change.",
                "output": out, "undo_commands": []}
    undo_cmds = [_acl_ctx(acl_name, t.type, acl_kind), original.strip()]
    undo_label = f"restore rule {seq} in {acl_name}"
    audit.log_warn(db, cu.username,
                   f"Deleted rule {seq} from {acl_name} on {t.label}",
                   f"Removed line: {original}\nCommands: {' ; '.join(cmds)}",
                   undo_commands=undo_cmds, undo_label=undo_label, switch_id=t.id,
                   event_type=db_models.EV_RULE_DELETE)
    return {"success": True,
            "message": f"Rule {seq} removed from {acl_name} on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "switch_id": t.id,
            "undo_commands": undo_cmds,
            "undo_label": undo_label}


@app.post("/api/write/acl-delete")
async def acl_delete(data: sch.AclDeleteRequest,
                     cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    ctx = _acl_ctx(acl_name, t.type, acl_kind)

    # Capture the full config (rules and remarks, verbatim) before deleting
    # so the ACL can be fully reconstructed on undo.
    raw_config = await asyncio.to_thread(
        svc.show, t, cu.username, f"show running-config | section {ctx}", timeout=30)
    undo_commands = _acl_config_lines(raw_config, ctx)
    if not undo_commands:
        return {"success": False,
                "message": f"ACL '{acl_name}' was not found on {t.label}. "
                           f"It may already be gone — refresh the ACL view.",
                "output": "", "undo_commands": []}

    cmds = [f"no {ctx}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds, timeout=45)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to delete ACL '{acl_name}' on {t.label}",
                        f"Problem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the delete command.",
                "output": out, "undo_commands": []}
    undo_label = f"restore ACL {acl_name}"
    audit.log_warn(db, cu.username,
                   f"Deleted ACL '{acl_name}' on {t.label}",
                   f"Removed {len(undo_commands) - 1} line(s)\nCommand: {cmds[0]}",
                   undo_commands=undo_commands, undo_label=undo_label, switch_id=t.id,
                   event_type=db_models.EV_ACL_DELETE)
    return {"success": True,
            "message": f"ACL '{acl_name}' deleted from {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo_commands, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/acl-sync-preview")
async def acl_sync_preview(data: sch.AclSyncRequest,
                           cu: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    """Compute (without applying) exactly which sequence numbers a sync
    would touch on the target, so the confirm dialog can show the real
    commands before anything is sent."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    source, target = _resolve_vpc_pair(
        [data.source_switch_id, data.target_switch_id], cu.username, db,
        require_write=True)
    cmds, _, _ = await _acl_sync_plan(acl_name, source, target, cu.username)
    if cmds is None:
        raise ValidationError(f"ACL '{acl_name}' does not exist on {source.label}.")
    return {"commands": cmds, "changed": len(cmds) > 1}


def _diff_acl_seqs(source_seqs: Dict[int, str], target_seqs: Dict[int, str]
                   ) -> Tuple[List[int], List[int]]:
    """Pure sequence-number diff: which seqs need removing from the target
    and which need (re)adding from the source, ignoring display-only
    annotations (NX-OS match counters, host/CIDR echo style). Identical
    sequences are left out of both lists entirely."""
    def differs(seq):
        return (seq not in target_seqs or seq not in source_seqs
                or _canonical_acl_rule(target_seqs[seq]) != _canonical_acl_rule(source_seqs[seq]))
    to_remove = sorted(seq for seq in target_seqs if differs(seq))
    to_add = sorted(seq for seq in source_seqs if differs(seq))
    return to_remove, to_add


async def _acl_seq_map_for_sync(t: "svc.SwitchTarget", username: str,
                                acl_name: str, ctx: str) -> Dict[int, str]:
    """Fetch one switch's sequence -> line map for an ACL, preferring the
    verbatim 'show running-config | section' capture (keeps remarks), but
    falling back to 'show ip access-lists <name>' — the same command the
    VPC diff view itself uses to decide an ACL exists — if the section
    fetch comes back empty. Some NX-OS builds don't reliably match `|
    section` against an ACL context line even though the ACL is really
    there, which was causing sync to wrongly report "does not exist" for
    ACLs the diff view had just confirmed were present."""
    raw = await asyncio.to_thread(
        svc.show, t, username, f"show running-config | section {ctx}", timeout=30)
    lines = _acl_config_lines(raw, ctx)
    if lines:
        return _acl_seq_map(lines)
    _, rule_lines = await asyncio.to_thread(svc.get_acl_rules, t, username, acl_name)
    if not rule_lines:
        return {}
    return _acl_seq_map([ctx] + [f" {line}" for line in rule_lines])


async def _acl_sync_plan(acl_name: str, source: "svc.SwitchTarget",
                         target: "svc.SwitchTarget", username: str):
    """Diff one ACL between source and target at the sequence-number level
    and return (commands, source_seqs, target_seqs) — commands is None if
    the ACL doesn't exist on the source (on neither the running-config
    capture nor the show-ip-access-lists fallback). Only sequences that
    actually differ (or are missing on one side) are touched; identical
    sequences (ignoring display-only annotations like NX-OS match
    counters) are left alone rather than wiping and rebuilding the whole
    ACL. If the ACL doesn't exist on the target at all, every source
    sequence ends up in to_add and none in to_remove, so it gets created
    from scratch with every rule."""
    ctx = f"ip access-list {acl_name}"
    source_seqs = await _acl_seq_map_for_sync(source, username, acl_name, ctx)
    if not source_seqs:
        return None, None, None
    target_seqs = await _acl_seq_map_for_sync(target, username, acl_name, ctx)
    to_remove, to_add = _diff_acl_seqs(source_seqs, target_seqs)

    cmds = [ctx] + [f"no {seq}" for seq in to_remove] + [source_seqs[seq].strip() for seq in to_add]
    return cmds, source_seqs, target_seqs


@app.post("/api/write/acl-sync")
async def acl_sync(data: sch.AclSyncRequest,
                   cu: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    """Sync one ACL on the target VPC-peer switch to match the source,
    touching only the sequence numbers that actually differ."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    source, target = _resolve_vpc_pair(
        [data.source_switch_id, data.target_switch_id], cu.username, db)
    ctx = f"ip access-list {acl_name}"

    cmds, source_seqs, target_seqs = await _acl_sync_plan(acl_name, source, target, cu.username)
    if cmds is None:
        raise ValidationError(f"ACL '{acl_name}' does not exist on {source.label}.")
    if len(cmds) == 1:
        return {"success": True, "changed": False,
                "message": f"'{acl_name}' is already in sync between "
                           f"{source.label} and {target.label}.",
                "output": "", "undo_commands": []}

    to_remove, to_add = _diff_acl_seqs(source_seqs, target_seqs)

    group_names = {g["name"].lower() for g in
                   await asyncio.to_thread(svc.get_object_groups, target, cu.username)}
    range_names = {r["name"].lower() for r in
                   await asyncio.to_thread(svc.get_time_ranges, target, cu.username)}
    missing = set()
    for seq in to_add:
        line = source_seqs[seq]
        for m in _GROUP_REF_RE.finditer(line):
            if m.group(1).lower() not in group_names:
                missing.add(m.group(1))
        for m in _TIME_RANGE_REF_RE.finditer(line):
            if m.group(1).lower() not in range_names:
                missing.add(m.group(1))
    if missing:
        return {"success": False,
                "message": f"Cannot sync '{acl_name}': {', '.join(sorted(missing))} "
                           f"does not exist on {target.label}. Create it there first, "
                           f"then retry.",
                "output": "", "undo_commands": []}

    undo_cmds = ([ctx] + [f"no {seq}" for seq in sorted(to_add)]
                + [target_seqs[seq].strip() for seq in sorted(to_remove)])

    ok, out, err = await asyncio.to_thread(svc.configure, target, cu.username, cmds, timeout=60)
    if not ok:
        rb_ok, rb_out, rb_err = await asyncio.to_thread(
            svc.configure, target, cu.username, undo_cmds, timeout=60)
        audit.log_error(db, cu.username,
                        f"Failed to sync ACL '{acl_name}' from {source.label} to {target.label}",
                        f"Problem: {err}\nRollback successful: {bool(rb_ok and not rb_err)}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the sync.",
                "output": out, "undo_commands": []}

    verify_raw = await asyncio.to_thread(
        svc.show, target, cu.username, f"show running-config | section {ctx}", timeout=30)
    verify_seqs = _acl_seq_map(_acl_config_lines(verify_raw, ctx))
    verified = all(_canonical_acl_rule(verify_seqs.get(seq, "")) == _canonical_acl_rule(line)
                  for seq, line in source_seqs.items())
    undo_label = f"restore previous {acl_name} on {target.label}"
    audit.log_warn(db, cu.username,
                   f"Synced ACL '{acl_name}' from {source.label} to {target.label}",
                   f"Changed sequence(s): {', '.join(str(s) for s in sorted(set(to_remove) | set(to_add)))}\n"
                   f"Commands: {' ; '.join(cmds)}"
                   + ("" if verified else
                      "\n\nWarning: post-sync verification did not match exactly."),
                   undo_commands=undo_cmds, undo_label=undo_label, switch_id=target.id)
    message = (f"ACL '{acl_name}' synced from {source.label} to {target.label} "
              f"({len(set(to_remove) | set(to_add))} sequence(s) changed). "
              f"Running-config only — use Save Config when ready.")
    if not verified:
        message += " Warning: the switch's post-sync output didn't match exactly — please review."
    return {"success": True, "message": message, "output": out,
            "switch_id": target.id, "verified": verified,
            "undo_commands": undo_cmds, "undo_label": undo_label}


@app.post("/api/write/rule-edit")
async def rule_edit(data: sch.RuleEditRequest,
                    cu: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    """Replace one ACL rule and restore the original if anything fails."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    requested_original = validate_acl_rule_line(data.original_rule)
    replacement = validate_acl_rule_line(data.new_rule)
    old_seq = _sequence_of(requested_original)
    new_seq = _sequence_of(replacement)
    if old_seq is None or new_seq is None:
        raise ValidationError(
            "Both the original and replacement rules need sequence numbers.")

    sw, pw, enable_pw = get_switch_and_password(
        data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    _, before_lines = await asyncio.to_thread(
        svc.get_acl_rules, t, cu.username, acl_name)
    current = next((line for line in before_lines
                    if _sequence_of(line) == old_seq), None)
    if current is None:
        raise ValidationError(
            f"Rule {old_seq} is no longer present in {acl_name}. Refresh ACL Viewer.")
    if _canonical_acl_rule(current) != _canonical_acl_rule(requested_original):
        raise ValidationError(
            f"Rule {old_seq} changed since ACL Viewer loaded it. Refresh before editing.")
    collision = next((line for line in before_lines
                      if _sequence_of(line) == new_seq and new_seq != old_seq), None)
    if collision:
        raise ValidationError(
            f"Sequence {new_seq} is already used by another rule in {acl_name}.")
    if _canonical_acl_rule(current) == _canonical_acl_rule(replacement):
        return {"success": True, "changed": False,
                "message": "The replacement is identical to the existing rule.",
                "output": "", "undo_commands": []}

    original = re.sub(r"(?:\s+\([^)]*\))+\s*$", "", current.strip(),
                      flags=re.IGNORECASE)
    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    context = _acl_ctx(acl_name, t.type, acl_kind)
    commands = [context, f"no {old_seq}", replacement]

    def restore_original() -> tuple:
        rollback = [context, f"no {new_seq}", original]
        rollback_ok, rollback_output, rollback_error = svc.configure(
            t, cu.username, rollback, timeout=45)
        try:
            restore_verify_output, restore_lines = svc.get_acl_rules(
                t, cu.username, acl_name)
            restored = _rule_was_applied(restore_lines, original)
        except ssh_manager.SSHError as exc:
            restore_verify_output, restored = str(exc), False
        detail = (f"{rollback_output}\n\nRestore verification response:\n"
                  f"{restore_verify_output}")
        return detail, bool(rollback_ok and not rollback_error and restored)

    ok, output, error = await asyncio.to_thread(
        svc.configure, t, cu.username, commands, timeout=45)
    if not ok:
        rollback_output, restored = await asyncio.to_thread(restore_original)
        combined = (f"Replacement response:\n{output}\n\n"
                    f"Original-rule restore response:\n{rollback_output}")
        restore_message = ("The original rule was restored." if restored else
                           "Restoration was attempted but could not be confirmed; "
                           "review the switch output immediately.")
        audit.log_error(
            db, cu.username,
            f"Failed to edit rule {old_seq} in {acl_name} on {t.label}",
            f"Original: {original}\nReplacement: {replacement}\n"
            f"Problem: {error}\n\n{combined}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": (error or "The switch rejected the replacement rule.")
                           + f" {restore_message}",
                "output": combined, "undo_commands": []}

    try:
        verification_output, after_lines = await asyncio.to_thread(
            svc.get_acl_rules, t, cu.username, acl_name)
    except ssh_manager.SSHError as exc:
        verification_output, after_lines = str(exc), []
    original_still_present = (old_seq != new_seq and
                              _rule_was_applied(after_lines, original))
    if not _rule_was_applied(after_lines, replacement) or original_still_present:
        rollback_output, restored = await asyncio.to_thread(restore_original)
        combined = (f"Replacement response:\n{output}\n\n"
                    f"Verification response:\n{verification_output}\n\n"
                    f"Original-rule restore response:\n{rollback_output}")
        message = ("The switch did not confirm the replacement rule. "
                   + ("The original rule was restored." if restored else
                      "Restoration was attempted but could not be confirmed; "
                      "review the switch output immediately."))
        audit.log_error(
            db, cu.username,
            f"Could not verify edited rule {old_seq} in {acl_name} on {t.label}",
            f"Original: {original}\nReplacement: {replacement}\n\n{combined}")
        return {"success": False, "message": message,
                "output": combined, "undo_commands": []}

    undo = [context, f"no {new_seq}", original]
    undo_label = f"restore rule {old_seq} in {acl_name}"
    audit.log_success(
        db, cu.username, f"Edited rule {old_seq} in {acl_name} on {t.label}",
        f"Original: {original}\nReplacement: {replacement}",
        undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_RULE_EDIT)
    return {"success": True, "changed": True,
            "message": f"Rule {old_seq} was replaced in {acl_name} on {t.label}. "
                       "Running-config only — use Save Config when ready.",
            "output": output, "verification_output": verification_output,
            "undo_commands": undo, "undo_label": undo_label,
            "switch_id": t.id}


@app.post("/api/write/acl-interface")
async def update_acl_interface(data: sch.ACLInterfaceUpdateRequest,
                               cu: User = Depends(require_admin),
                               db: Session = Depends(get_db)):
    """Attach or detach an ACL on one VLAN interface, with verification."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    interface = validate_vlan_interface(data.interface)
    direction = (data.direction or "").strip().lower()
    if direction not in ("in", "out"):
        raise ValidationError("ACL direction must be inbound or outbound.")
    action = (data.action or "").strip().lower()
    if action not in ("attach", "detach"):
        raise ValidationError("ACL interface action must be attach or detach.")

    sw, pw, enable_pw = get_switch_and_password(
        data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    names = await asyncio.to_thread(svc.list_acl_names, t, cu.username)
    if acl_name not in names:
        raise ValidationError(f"ACL '{acl_name}' does not exist on {t.label}.")
    interface_output = await asyncio.to_thread(
        svc.show, t, cu.username, f"show running-config interface {interface}")
    interface_error = ssh_manager.detect_switch_error(interface_output)
    interface_exists = re.search(
        rf"^\s*interface\s+{re.escape(interface)}\s*$",
        interface_output, re.IGNORECASE | re.MULTILINE)
    if interface_error or not interface_exists:
        raise ValidationError(
            f"VLAN interface {interface} does not exist on {t.label}. "
            "No configuration command was sent.")
    before = acl_parser.parse_interface_acl(interface_output)
    exact = any(row["acl_name"].lower() == acl_name.lower()
                and row["direction"] == direction for row in before)
    if action == "attach" and exact:
        return {"success": True, "changed": False,
                "message": f"{acl_name} is already applied {direction}bound on {interface}.",
                "output": "", "undo_commands": []}
    if action == "attach":
        conflict = next((row for row in before
                         if row["direction"] == direction), None)
        if conflict:
            raise ValidationError(
                f"{interface} already has ACL '{conflict['acl_name']}' applied "
                f"{direction}bound. Remove it before applying another ACL.")
    if action == "detach" and not exact:
        raise ValidationError(
            f"{acl_name} is not applied {direction}bound on {interface}. Refresh ACL Viewer.")

    interface_context = f"interface {interface}"
    binding = f"ip access-group {acl_name} {direction}"
    change = binding if action == "attach" else f"no {binding}"
    rollback = [interface_context,
                f"no {binding}" if action == "attach" else binding]
    ok, output, error = await asyncio.to_thread(
        svc.configure, t, cu.username, [interface_context, change], timeout=45)
    if not ok:
        rollback_ok, rollback_output, rollback_error = await asyncio.to_thread(
            svc.configure, t, cu.username, rollback, timeout=45)
        combined = (f"Configuration response:\n{output}\n\n"
                    f"Rollback response:\n{rollback_output}")
        audit.log_error(
            db, cu.username,
            f"Failed to {action} ACL {acl_name} on {interface} on {t.label}",
            f"Problem: {error}\nRollback successful: "
            f"{bool(rollback_ok and not rollback_error)}\n\n{combined}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": error or "The switch rejected the VLAN ACL change.",
                "output": combined, "undo_commands": []}

    try:
        verification_output = await asyncio.to_thread(
            svc.show, t, cu.username, f"show running-config interface {interface}")
        after = acl_parser.parse_interface_acl(verification_output)
    except ssh_manager.SSHError as exc:
        verification_output, after = str(exc), []
    now_exact = any(row["acl_name"].lower() == acl_name.lower()
                    and row["direction"] == direction for row in after)
    verified = now_exact if action == "attach" else not now_exact
    if not verified:
        rollback_ok, rollback_output, rollback_error = await asyncio.to_thread(
            svc.configure, t, cu.username, rollback, timeout=45)
        try:
            rollback_verify_output = await asyncio.to_thread(
                svc.show, t, cu.username, f"show running-config interface {interface}")
            rollback_rows = acl_parser.parse_interface_acl(rollback_verify_output)
            rollback_exact = any(
                row["acl_name"].lower() == acl_name.lower()
                and row["direction"] == direction for row in rollback_rows)
            rollback_restored = ((not rollback_exact) if action == "attach"
                                 else rollback_exact)
        except ssh_manager.SSHError as exc:
            rollback_verify_output, rollback_restored = str(exc), False
        combined = (f"Configuration response:\n{output}\n\n"
                    f"Verification response:\n{verification_output}\n\n"
                    f"Rollback response:\n{rollback_output}\n\n"
                    f"Rollback verification response:\n{rollback_verify_output}")
        restored = bool(rollback_ok and not rollback_error and rollback_restored)
        message = ("The switch did not confirm the VLAN ACL change. "
                   + ("The previous interface configuration was restored."
                      if restored else
                      "Rollback was attempted but could not be confirmed; "
                      "review the switch output immediately."))
        audit.log_error(
            db, cu.username,
            f"Could not verify ACL {acl_name} on {interface} on {t.label}",
            f"Rollback confirmed: {restored}\n\n{combined}")
        return {"success": False,
                "message": message,
                "output": combined, "undo_commands": []}

    verb = "Applied" if action == "attach" else "Removed"
    undo_label = ((f"remove {acl_name} {direction}bound from {interface}")
                  if action == "attach" else
                  (f"restore {acl_name} {direction}bound on {interface}"))
    audit.log_success(
        db, cu.username,
        f"{verb} ACL {acl_name} {direction}bound on {interface} on {t.label}",
        f"Command: {change}", undo_commands=rollback,
        undo_label=undo_label, switch_id=t.id)
    return {"success": True, "changed": True,
            "message": f"{verb} {acl_name} {direction}bound on {interface} on {t.label}. "
                       "Running-config only — use Save Config when ready.",
            "output": output, "verification_output": verification_output,
            "undo_commands": rollback, "undo_label": undo_label,
            "switch_id": t.id}


@app.post("/api/write/acl-interface-flip")
async def flip_acl_interface(data: sch.ACLInterfaceFlipRequest,
                             cu: User = Depends(require_admin),
                             db: Session = Depends(get_db)):
    """Move an ACL binding from inbound to outbound (or back) on one VLAN
    interface. Both commands go in a single config session so the ACL is
    never momentarily off the interface, and the binding is verified
    afterwards with a rollback if the switch did not take it."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    interface = validate_vlan_interface(data.interface)
    current = (data.direction or "").strip().lower()
    if current not in ("in", "out"):
        raise ValidationError("ACL direction must be inbound or outbound.")
    target = "out" if current == "in" else "in"

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    interface_output = await asyncio.to_thread(
        svc.show, t, cu.username, f"show running-config interface {interface}")
    if ssh_manager.detect_switch_error(interface_output) or not re.search(
            rf"^\s*interface\s+{re.escape(interface)}\s*$",
            interface_output, re.IGNORECASE | re.MULTILINE):
        raise ValidationError(
            f"VLAN interface {interface} does not exist on {t.label}. "
            "No configuration command was sent.")
    before = acl_parser.parse_interface_acl(interface_output)
    if not any(r["acl_name"].lower() == acl_name.lower() and r["direction"] == current
               for r in before):
        raise ValidationError(
            f"{acl_name} is not applied {current}bound on {interface} any more. "
            "Reload the ACL before retrying.")
    occupant = next((r for r in before if r["direction"] == target
                     and r["acl_name"].lower() != acl_name.lower()), None)
    if occupant:
        raise ValidationError(
            f"{interface} already has ACL '{occupant['acl_name']}' applied "
            f"{target}bound. Remove it before moving {acl_name} there.")

    ctx = f"interface {interface}"
    cmds = [ctx, f"no ip access-group {acl_name} {current}",
            f"ip access-group {acl_name} {target}"]
    rollback = [ctx, f"no ip access-group {acl_name} {target}",
                f"ip access-group {acl_name} {current}"]
    ok, output, error = await asyncio.to_thread(
        svc.configure, t, cu.username, cmds, timeout=45)

    verification_output = ""
    verified = False
    if ok:
        try:
            verification_output = await asyncio.to_thread(
                svc.show, t, cu.username, f"show running-config interface {interface}")
            after = acl_parser.parse_interface_acl(verification_output)
        except ssh_manager.SSHError as exc:
            verification_output, after = str(exc), []
        verified = any(r["acl_name"].lower() == acl_name.lower()
                       and r["direction"] == target for r in after)

    if not ok or not verified:
        rb_ok, rb_output, rb_error = await asyncio.to_thread(
            svc.configure, t, cu.username, rollback, timeout=45)
        combined = (f"Configuration response:\n{output}\n\n"
                    f"Verification response:\n{verification_output}\n\n"
                    f"Rollback response:\n{rb_output}")
        audit.log_error(
            db, cu.username,
            f"Failed to move ACL {acl_name} to {target}bound on {interface} on {t.label}",
            f"Problem: {error}\nRollback successful: {bool(rb_ok and not rb_error)}\n\n{combined}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": (error or "The switch did not confirm the direction change.")
                           + (" The original binding was restored."
                              if rb_ok and not rb_error else
                              " Rollback could not be confirmed — review the switch."),
                "output": combined, "undo_commands": []}
    undo_label = f"put {acl_name} back {current}bound on {interface}"
    audit.log_warn(
        db, cu.username,
        f"Moved ACL {acl_name} from {current}bound to {target}bound on {interface} "
        f"on {t.label}",
        f"Commands: {' ; '.join(cmds)}", undo_commands=rollback,
        undo_label=undo_label, switch_id=t.id)
    return {"success": True,
            "message": f"{acl_name} is now applied {target}bound on {interface} on "
                       f"{t.label}. Running-config only — use Save Config when ready.",
            "output": output, "verification_output": verification_output,
            "undo_commands": rollback, "undo_label": undo_label,
            "switch_id": t.id, "direction": target}


@app.post("/api/write/summary-apply")
async def summary_apply(data: sch.SummaryApplyRequest,
                        cu: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    summary  = validate_permit_rule_line(data.summary_rule)
    if not data.rules_to_remove:
        raise ValidationError("No rules were selected for replacement.")
    seqs = [validate_sequence(s) for s in data.rules_to_remove]
    seqs = sorted({s for s in seqs if s is not None})

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    _, lines = await asyncio.to_thread(svc.get_acl_rules, t, cu.username, acl_name)
    originals = [l.strip() for l in lines
                 if any(re.match(rf"^{s}\s", l.strip()) for s in seqs)]
    if len(originals) != len(seqs):
        raise ValidationError(
            "The ACL has changed since the suggestion was generated. "
            "Re-run the analysis before applying.")

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    cmds = [_acl_ctx(acl_name, t.type, acl_kind)] + [f"no {s}" for s in seqs] + [summary]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds, timeout=45)

    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to apply a summary rule to {acl_name} on {t.label}",
                        f"Commands: {' ; '.join(cmds)}\nProblem: {err}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the summary rule. "
                                  "Verify the ACL on the switch.",
                "output": out, "undo_commands": []}

    seq_m = re.match(r"^(\d+)\s", summary)
    undo  = [_acl_ctx(acl_name, t.type, acl_kind)]
    if seq_m:
        undo.append(f"no {seq_m.group(1)}")
    undo += originals
    undo_label = f"restore the {len(seqs)} original rule(s) in {acl_name}"
    audit.log_success(db, cu.username,
                      f"Applied a summary rule to {acl_name} on {t.label}",
                      f"Removed sequences: {', '.join(map(str, seqs))}\n"
                      f"Removed lines:\n" + "\n".join(originals) +
                      f"\n\nAdded: {summary}",
                      undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_SUMMARY_APPLY)
    return {"success": True,
            "message": f"Replaced {len(seqs)} rule(s) with the summary rule "
                       f"in {acl_name} on {t.label}. Running-config only.",
            "output": out, "undo_commands": undo, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/analysis/reverse-direction-preview")
async def reverse_direction_preview(data: sch.ReverseDirectionRequest,
                                    cu: User = Depends(require_admin),
                                    db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)
    svc.require_write_access(t)

    _, lines = await asyncio.to_thread(svc.get_acl_rules, t, cu.username, acl_name)
    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    group_types = {g["name"]: g["kind"] for g in
                   await asyncio.to_thread(svc.get_object_groups, t, cu.username)}
    plan = acl_parser.plan_acl_reversal(lines, t.type, group_types, acl_kind)
    # Where the ACL is bound matters here as much as the rules do: reversing
    # source/destination without also moving the binding to the opposite
    # direction usually leaves the ACL filtering the wrong way round.
    bindings = (await asyncio.to_thread(svc.map_acl_interfaces, t, cu.username)
                ).get(acl_name, [])
    return {"switch_id": t.id, "acl_name": acl_name, "acl_kind": acl_kind,
            "total_rules": len(lines), "applied_on": bindings, **plan}


@app.post("/api/write/reverse-direction-apply")
async def reverse_direction_apply(data: sch.ReverseDirectionApplyRequest,
                                  cu: User = Depends(require_admin),
                                  db: Session = Depends(get_db)):
    acl_name = validate_identifier(data.acl_name, "ACL name")
    if not data.sequences:
        raise ValidationError("No rules were selected for reversal.")
    seqs = sorted({validate_sequence(s) for s in data.sequences})

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    t = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)

    _, lines = await asyncio.to_thread(svc.get_acl_rules, t, cu.username, acl_name)
    acl_kind = await asyncio.to_thread(svc.get_acl_kind, t, cu.username, acl_name)
    group_types = {g["name"]: g["kind"] for g in
                   await asyncio.to_thread(svc.get_object_groups, t, cu.username)}
    plan = acl_parser.plan_acl_reversal(lines, t.type, group_types, acl_kind)

    reversible_by_seq = {r["sequence"]: r for r in plan["reversible"] if r["sequence"] is not None}
    missing = [s for s in seqs if s not in reversible_by_seq]
    if missing:
        raise ValidationError(
            "The ACL has changed since the plan was generated, or the requested "
            f"sequence(s) {', '.join(map(str, missing))} can no longer be auto-reversed. "
            "Re-run the preview before applying.")

    ctx = _acl_ctx(acl_name, t.type, acl_kind)
    cmds = [ctx]
    undo = [ctx]
    for s in seqs:
        entry = reversible_by_seq[s]
        cmds.append(f"no {s}")
        cmds.append(entry["reversed"])
        undo.append(f"no {s}")
        undo.append(entry["original"])

    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds, timeout=60)
    if not ok:
        rb_ok, rb_out, rb_err = await asyncio.to_thread(
            svc.configure, t, cu.username, undo, timeout=60)
        audit.log_error(db, cu.username,
                        f"Failed to reverse rule direction in {acl_name} on {t.label}",
                        f"Commands: {' ; '.join(cmds)}\nProblem: {err}\n"
                        f"Rollback successful: {bool(rb_ok and not rb_err)}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the reversed rules.",
                "output": out, "undo_commands": []}
    undo_label = f"restore the original direction of {len(seqs)} rule(s) in {acl_name}"
    audit.log_warn(db, cu.username,
                   f"Reversed direction of {len(seqs)} rule(s) in {acl_name} on {t.label}",
                   f"Sequences: {', '.join(map(str, seqs))}\nCommands: {' ; '.join(cmds)}",
                   undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                   event_type=db_models.EV_REVERSE_APPLY)
    return {"success": True,
            "message": f"Reversed {len(seqs)} rule(s) in {acl_name} on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo, "undo_label": undo_label, "switch_id": t.id}


# ═══════════════════════ TEMPLATES ═══════════════════════

def _template_visible_or_404(db: Session, cu: User, template_id: int) -> Template:
    t = db.query(Template).filter(Template.id == template_id).first()
    if not t:
        raise HTTPException(404, "That template no longer exists.")
    if t.owner_username != cu.username:
        shared = db.query(TemplateShare).filter(
            TemplateShare.template_id == t.id,
            TemplateShare.username == cu.username).first()
        if not shared:
            raise HTTPException(404, "That template no longer exists.")
    return t


def _template_out(t: Template, cu_username: str, shared_with: List[str]) -> Dict[str, Any]:
    return {
        "id": t.id, "name": t.name, "switch_type": t.switch_type,
        "acl_kind": t.acl_kind or "extended",
        "direction": t.direction,
        "lines": json.loads(t.lines),
        "reversed_lines": json.loads(t.reversed_lines),
        "skipped_reversal_count": t.skipped_reversal_count,
        "owner_username": t.owner_username,
        "is_owner": t.owner_username == cu_username,
        "shared_with": shared_with,
    }


def _template_name_conflict(db: Session, username: str, name: str,
                            exclude_template_id: Optional[int] = None) -> bool:
    """True if `username` already has a template (owned, or shared with
    them) called `name` — case-insensitively, since it would appear
    alongside their own templates in the same list."""
    shared_ids = [s.template_id for s in db.query(TemplateShare)
                 .filter(TemplateShare.username == username).all()]
    q = db.query(Template).filter(Template.name.ilike(name))
    if shared_ids:
        q = q.filter((Template.owner_username == username) | (Template.id.in_(shared_ids)))
    else:
        q = q.filter(Template.owner_username == username)
    matches = q.all()
    if exclude_template_id is not None:
        matches = [t for t in matches if t.id != exclude_template_id]
    return bool(matches)


def _validate_template_input(data, db: Session, cu: User,
                             exclude_template_id: Optional[int] = None):
    name = validate_identifier(data.name, "Template name")
    switch_type = (data.switch_type or "").strip().lower()
    if switch_type not in ("ios", "nexus"):
        raise ValidationError("Platform must be 'ios' or 'nexus'.")
    # NX-OS has no standard/extended split in this app's model -- only IOS
    # templates can choose; nexus always stores "extended".
    acl_kind = (data.acl_kind or "extended").strip().lower() if switch_type == "ios" else "extended"
    if acl_kind not in ("standard", "extended"):
        raise ValidationError("ACL kind must be 'standard' or 'extended'.")
    direction = (data.direction or "").strip().lower()
    if direction not in ("in", "out"):
        raise ValidationError("Direction must be 'in' or 'out'.")
    if not data.lines:
        raise ValidationError("Add at least one rule line.")

    validated_lines = []
    for i, line in enumerate(data.lines, start=1):
        try:
            v = validate_acl_rule_line(line)
        except ValidationError as e:
            raise ValidationError(f"Line {i}: {e}")
        group_types = {} if switch_type == "nexus" else acl_parser._infer_ios_group_kinds(v)
        if not acl_parser.parse_acl_rule(v, switch_type, group_types, acl_kind):
            kind_label = f"{switch_type.upper()} {acl_kind}"
            raise ValidationError(
                f"Line {i}: '{v}' isn't valid {kind_label} ACL rule syntax — "
                f"check the address/protocol/ports, then try again.")
        validated_lines.append(v)

    share_usernames = []
    if data.share_with:
        for uname in data.share_with:
            u = db.query(User).filter(User.username == uname).first()
            if not u:
                raise ValidationError(f"User '{uname}' does not exist.")
            if u.role not in ADMIN_ROLES:
                raise ValidationError(
                    f"'{uname}' is not an admin — templates can only be shared with admins.")
            if u.username != cu.username and u.username not in share_usernames:
                share_usernames.append(u.username)

    if _template_name_conflict(db, cu.username, name, exclude_template_id):
        raise ValidationError(
            f"You already have a template named '{name}'. Pick another name.")
    for uname in share_usernames:
        if _template_name_conflict(db, uname, name, exclude_template_id):
            raise ValidationError(
                f"'{uname}' already has a template named '{name}'. Pick another name.")

    return name, switch_type, acl_kind, direction, validated_lines, share_usernames


@app.get("/api/templates")
async def list_templates(cu: User = Depends(require_admin), db: Session = Depends(get_db)):
    owned = db.query(Template).filter(Template.owner_username == cu.username).all()
    shared_ids = [s.template_id for s in
                 db.query(TemplateShare).filter(TemplateShare.username == cu.username).all()]
    shared = (db.query(Template).filter(Template.id.in_(shared_ids)).all()
             if shared_ids else [])
    all_templates = owned + shared
    all_ids = [t.id for t in all_templates]
    shares_by_template: Dict[int, List[str]] = {}
    if all_ids:
        for s in db.query(TemplateShare).filter(TemplateShare.template_id.in_(all_ids)).all():
            shares_by_template.setdefault(s.template_id, []).append(s.username)
    return {"templates": [_template_out(t, cu.username, shares_by_template.get(t.id, []))
                          for t in all_templates]}


@app.get("/api/templates/share-candidates")
async def template_share_candidates(cu: User = Depends(require_admin),
                                    db: Session = Depends(get_db)):
    users = db.query(User).filter(User.role.in_(ADMIN_ROLES),
                                  User.username != cu.username).all()
    return {"users": [{"username": u.username, "role": u.role} for u in users]}


@app.post("/api/templates")
async def create_template(data: sch.TemplateCreate,
                          cu: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    name, switch_type, acl_kind, direction, lines, share_usernames = \
        _validate_template_input(data, db, cu)
    reversed_lines, skipped = acl_parser.build_reversed_template_lines(lines, switch_type, acl_kind)

    t = Template(name=name, owner_username=cu.username, switch_type=switch_type,
                acl_kind=acl_kind, direction=direction, lines=json.dumps(lines),
                reversed_lines=json.dumps(reversed_lines),
                skipped_reversal_count=skipped)
    db.add(t)
    db.commit()
    db.refresh(t)
    for uname in share_usernames:
        db.add(TemplateShare(template_id=t.id, username=uname))
    db.commit()

    audit.log_success(db, cu.username, f"Created template '{name}'",
                      f"Platform: {switch_type} ({acl_kind}), direction: {direction}, "
                      f"{len(lines)} line(s)" +
                      (f", shared with: {', '.join(share_usernames)}" if share_usernames else ""))
    return _template_out(t, cu.username, share_usernames)


@app.put("/api/templates/{template_id}")
async def update_template(template_id: int, data: sch.TemplateUpdate,
                          cu: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    t = db.query(Template).filter(Template.id == template_id).first()
    if not t:
        raise HTTPException(404, "That template no longer exists.")
    if t.owner_username != cu.username:
        raise HTTPException(403, "Only the template's owner can edit it.")

    name, switch_type, acl_kind, direction, lines, share_usernames = _validate_template_input(
        data, db, cu, exclude_template_id=t.id)
    reversed_lines, skipped = acl_parser.build_reversed_template_lines(lines, switch_type, acl_kind)

    t.name = name
    t.switch_type = switch_type
    t.acl_kind = acl_kind
    t.direction = direction
    t.lines = json.dumps(lines)
    t.reversed_lines = json.dumps(reversed_lines)
    t.skipped_reversal_count = skipped
    db.query(TemplateShare).filter(TemplateShare.template_id == t.id)\
                           .delete(synchronize_session=False)
    for uname in share_usernames:
        db.add(TemplateShare(template_id=t.id, username=uname))
    db.commit()
    db.refresh(t)

    audit.log_success(db, cu.username, f"Updated template '{name}'",
                      f"Platform: {switch_type}, direction: {direction}, {len(lines)} line(s)")
    return _template_out(t, cu.username, share_usernames)


@app.delete("/api/templates/{template_id}")
async def delete_template(template_id: int, cu: User = Depends(require_admin),
                          db: Session = Depends(get_db)):
    t = db.query(Template).filter(Template.id == template_id).first()
    if not t:
        raise HTTPException(404, "That template no longer exists.")
    if t.owner_username != cu.username:
        raise HTTPException(403, "Only the template's owner can delete it.")
    name = t.name
    db.query(TemplateShare).filter(TemplateShare.template_id == t.id)\
                           .delete(synchronize_session=False)
    db.delete(t)
    db.commit()
    audit.log_warn(db, cu.username, f"Deleted template '{name}'", "")
    return {"message": f"Template '{name}' was deleted."}


def _missing_group_or_range_refs(st, cu_username: str, lines: List[str]) -> set:
    """Names referenced by addrgroup/portgroup (NX-OS) or object-group (IOS)
    and time-range that don't actually exist on the target switch. Runs
    synchronously -- callers wrap it in asyncio.to_thread."""
    group_names = {g["name"].lower() for g in svc.get_object_groups(st, cu_username)}
    range_names = {r["name"].lower() for r in svc.get_time_ranges(st, cu_username)}
    missing = set()
    is_nxos = st.type == "nexus"
    group_ref_re = _GROUP_REF_RE if is_nxos else re.compile(r"\bobject-group\s+(\S+)", re.IGNORECASE)
    for line in lines:
        for m in group_ref_re.finditer(line):
            if m.group(1).lower() not in group_names:
                missing.add(m.group(1))
        for m in _TIME_RANGE_REF_RE.finditer(line):
            if m.group(1).lower() not in range_names:
                missing.add(m.group(1))
    return missing


async def _build_template_apply_plan(data, cu: User, db: Session):
    """Shared by the preview and apply endpoints: resolve everything and
    compute the exact commands, without writing anything. Raises
    ValidationError on any problem."""
    t = _template_visible_or_404(db, cu, data.template_id)
    acl_name = validate_identifier(data.acl_name, "ACL name")
    direction = (data.direction or "").strip().lower()
    if direction not in ("in", "out"):
        raise ValidationError("Direction must be 'in' or 'out'.")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    st = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)
    # Both builders back a preview as well as an apply, so guarding here
    # covers the preview too — it stages a change and must not run on a
    # switch this person can only read.
    svc.require_write_access(st)
    if st.type != t.switch_type:
        raise ValidationError(
            f"Template '{t.name}' is for {t.switch_type.upper()} switches; "
            f"{st.label} is {st.type.upper()}.")

    lines = json.loads(t.lines if direction == t.direction else t.reversed_lines)
    if not lines:
        raise ValidationError(
            f"Template '{t.name}' has no rule(s) for the {direction}bound direction.")

    acl_kind = await asyncio.to_thread(svc.get_acl_kind, st, cu.username, acl_name)
    template_kind = (t.acl_kind or "extended").lower()
    if (acl_kind or "extended").lower() != template_kind:
        raise ValidationError(
            f"Template '{t.name}' is a {template_kind} template; '{acl_name}' is a "
            f"{(acl_kind or 'extended').lower()} ACL on {st.label}.")

    missing = await asyncio.to_thread(_missing_group_or_range_refs, st, cu.username, lines)
    if missing:
        raise ValidationError(
            f"Cannot apply '{t.name}': {', '.join(sorted(missing))} does not exist on "
            f"{st.label}. Create it there first, then retry.")

    _, existing_lines = await asyncio.to_thread(svc.get_acl_rules, st, cu.username, acl_name)
    existing_seqs = [s for s in (acl_parser._sequence_of(l) for l in existing_lines) if s is not None]
    seqs = acl_parser.first_empty_sequences(existing_seqs, len(lines))

    ctx = _acl_ctx(acl_name, st.type, acl_kind)
    cmds = [ctx] + [f"{seq} {line}" for seq, line in zip(seqs, lines)]
    return t, st, acl_name, acl_kind, direction, lines, seqs, ctx, cmds


@app.post("/api/analysis/template-apply-preview")
async def template_apply_preview(data: sch.TemplateApplyRequest,
                                 cu: User = Depends(require_admin),
                                 db: Session = Depends(get_db)):
    t, st, acl_name, acl_kind, direction, lines, seqs, ctx, cmds = \
        await _build_template_apply_plan(data, cu, db)
    return {"commands": cmds, "acl_name": acl_name, "switch_id": st.id}


@app.post("/api/write/template-apply")
async def apply_template(data: sch.TemplateApplyRequest,
                         cu: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    t, st, acl_name, acl_kind, direction, lines, seqs, ctx, cmds = \
        await _build_template_apply_plan(data, cu, db)
    ok, out, err = await asyncio.to_thread(svc.configure, st, cu.username, cmds, timeout=60)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to apply template '{t.name}' to {acl_name} on {st.label}",
                        f"Commands: {' ; '.join(cmds)}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the template's rules.",
                "output": out, "undo_commands": []}
    undo = [ctx] + [f"no {seq}" for seq in seqs]
    undo_label = f"remove the {len(lines)} rule(s) added from template '{t.name}'"
    audit.log_warn(db, cu.username,
                   f"Applied template '{t.name}' ({direction}bound) to {acl_name} on {st.label}",
                   f"Sequences: {', '.join(map(str, seqs))}\nCommands: {' ; '.join(cmds)}",
                   undo_commands=undo, undo_label=undo_label, switch_id=st.id,
                   event_type=db_models.EV_TEMPLATE_APPLY)
    message = (f"Added {len(lines)} rule(s) from template '{t.name}' to {acl_name} on "
              f"{st.label}. Running-config only — use Save Config when ready.")
    if direction != t.direction and t.skipped_reversal_count:
        message += (f" Note: {t.skipped_reversal_count} line(s) in the original "
                   f"({t.direction}bound) direction referenced an IOS object-group and "
                   f"couldn't be auto-reversed — they aren't included here. Author a "
                   f"separate template manually (under a different name) if you need them.")
    return {"success": True, "message": message, "output": out,
            "undo_commands": undo, "undo_label": undo_label, "switch_id": st.id}


async def _build_acl_create_plan(data: sch.AclCreateRequest, cu: User, db: Session):
    """Shared by the preview and create endpoints: resolve everything and
    compute the exact commands for a brand-new ACL, without writing
    anything. Raises ValidationError on any problem."""
    acl_name = validate_identifier(data.acl_name, "ACL name")
    switch_type = (data.switch_type or "").strip().lower()
    if switch_type not in ("ios", "nexus"):
        raise ValidationError("Platform must be 'ios' or 'nexus'.")
    # NX-OS has no standard/extended split in this app's model -- only IOS
    # ACLs can choose; nexus always creates "extended".
    acl_kind = (data.acl_kind or "extended").strip().lower() if switch_type == "ios" else "extended"
    if acl_kind not in ("standard", "extended"):
        raise ValidationError("ACL kind must be 'standard' or 'extended'.")
    implicit_action = (data.implicit_action or "").strip().lower()
    if implicit_action not in ("permit", "deny"):
        raise ValidationError("Implicit rule must be 'permit' or 'deny'.")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    st = svc.SwitchTarget(sw, pw, sw.ssh_username or cu.username, enable_pw)
    # Both builders back a preview as well as an apply, so guarding here
    # covers the preview too — it stages a change and must not run on a
    # switch this person can only read.
    svc.require_write_access(st)
    if st.type != switch_type:
        raise ValidationError(
            f"'{acl_name}' would be created as a {switch_type.upper()} ACL; "
            f"{st.label} is {st.type.upper()}.")

    existing_names = {n.lower() for n in
                      await asyncio.to_thread(svc.list_acl_names, st, cu.username)}
    if acl_name.lower() in existing_names:
        raise ValidationError(
            f"'{acl_name}' already exists on {st.label}. Use Add ACL Rule to modify it.")

    lines: List[str] = []
    t = None
    if data.template_id is not None:
        t = _template_visible_or_404(db, cu, data.template_id)
        if t.switch_type != switch_type:
            raise ValidationError(
                f"Template '{t.name}' is for {t.switch_type.upper()} switches; "
                f"this ACL is {switch_type.upper()}.")
        if (t.acl_kind or "extended").lower() != acl_kind:
            raise ValidationError(
                f"Template '{t.name}' is a {(t.acl_kind or 'extended')} template; "
                f"this ACL is {acl_kind}.")
        direction = (data.direction or "").strip().lower()
        if direction not in ("in", "out"):
            raise ValidationError("Direction must be 'in' or 'out'.")
        lines = json.loads(t.lines if direction == t.direction else t.reversed_lines)
        if not lines:
            raise ValidationError(
                f"Template '{t.name}' has no rule(s) for the {direction}bound direction.")
        missing = await asyncio.to_thread(_missing_group_or_range_refs, st, cu.username, lines)
        if missing:
            raise ValidationError(
                f"Cannot use template '{t.name}': {', '.join(sorted(missing))} does not exist "
                f"on {st.label}. Create it there first, then retry.")

    seqs = acl_parser.first_empty_sequences([], len(lines))
    if seqs and seqs[-1] >= 999:
        raise ValidationError(
            "That template has too many lines to leave room for the implicit rule at sequence 999.")

    implicit_line = (f"{implicit_action} ip any any" if acl_kind == "extended"
                     else f"{implicit_action} any")
    ctx = _acl_ctx(acl_name, st.type, acl_kind)
    cmds = ([ctx] + [f"{seq} {line}" for seq, line in zip(seqs, lines)]
           + [f"999 {implicit_line}"])
    return st, acl_name, t, implicit_action, lines, ctx, cmds


@app.post("/api/analysis/acl-create-preview")
async def acl_create_preview(data: sch.AclCreateRequest,
                             cu: User = Depends(require_admin),
                             db: Session = Depends(get_db)):
    st, acl_name, t, implicit_action, lines, ctx, cmds = await _build_acl_create_plan(data, cu, db)
    return {"commands": cmds, "acl_name": acl_name, "switch_id": st.id}


@app.post("/api/write/acl-create")
async def acl_create(data: sch.AclCreateRequest,
                     cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    st, acl_name, t, implicit_action, lines, ctx, cmds = await _build_acl_create_plan(data, cu, db)
    ok, out, err = await asyncio.to_thread(svc.configure, st, cu.username, cmds, timeout=45)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to create ACL '{acl_name}' on {st.label}",
                        f"Commands: {' ; '.join(cmds)}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the create command.",
                "output": out, "undo_commands": []}
    undo_commands = [f"no {ctx}"]
    undo_label = f"delete ACL {acl_name}"
    note = f" using {len(lines)} rule(s) from template '{t.name}'" if t else ""
    audit.log_warn(db, cu.username,
                   f"Created ACL '{acl_name}' on {st.label}",
                   f"Commands: {' ; '.join(cmds)}",
                   undo_commands=undo_commands, undo_label=undo_label, switch_id=st.id,
                   event_type=db_models.EV_ACL_CREATE)
    return {"success": True,
            "message": f"ACL '{acl_name}' created on {st.label}{note}, with an implicit "
                       f"{implicit_action} at sequence 999. Running-config only — use Save "
                       f"Config when ready.",
            "output": out, "undo_commands": undo_commands, "switch_id": st.id,
            "undo_label": undo_label}


@app.post("/api/write/time-range-preview")
async def tr_preview(data: sch.TimeRangePreviewRequest,
                     cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    try:
        name = validate_identifier(data.name, "Time-range name")

        entries = []
        for i, e in enumerate(data.entries, start=1):
            kind = (e.type or "").strip().lower()
            if kind == "periodic":
                # For periodic entries, start_time and end_time are required
                if not e.start_time:
                    raise ValidationError(f"Entry {i}: start time is required for periodic entries.")
                if not e.end_time:
                    raise ValidationError(f"Entry {i}: end time is required for periodic entries.")
                
                entries.append({
                    "type": "periodic",
                    "days": validate_days(e.days or "daily"),
                    "start_time": validate_time(e.start_time, f"Entry {i} start time"),
                    "end_time":   validate_time(e.end_time, f"Entry {i} end time"),
                })
                if entries[-1]["start_time"] >= entries[-1]["end_time"]:
                    raise ValidationError(
                        f"Entry {i}: the start time must be earlier than the end time.")
            elif kind == "absolute":
                item = {"type": "absolute"}
                if e.start_time or e.start_date:
                    if e.start_time:
                        item["start_time"] = validate_time(e.start_time, f"Entry {i} start time")
                    if e.start_date:
                        item["start_date"] = validate_cisco_date(e.start_date, f"Entry {i} start date")
                if e.end_time or e.end_date:
                    if e.end_time:
                        item["end_time"] = validate_time(e.end_time, f"Entry {i} end time")
                    if e.end_date:
                        item["end_date"] = validate_cisco_date(e.end_date, f"Entry {i} end date")
                if len(item) == 1:
                    raise ValidationError(
                        f"Entry {i}: provide a start and/or end date and time.")
                entries.append(item)
            else:
                raise ValidationError(
                    f"Entry {i}: type must be either periodic or absolute.")

        # Resolve switches only after the entries validate, so input errors surface first
        targets = svc.resolve_targets(data.switch_ids, cu.username, db, require_write=True)
        commands = rule_generator.build_time_range_commands(name, entries)
        return {"name": name, "commands": commands,
                "switches": [{"switch_id": t.id, "switch_name": t.label} for t in targets],
                "message": "Review the commands below, then apply."}
    except Exception as ex:
        import traceback
        print(f"[ERROR] Time-range preview failed: {type(ex).__name__}: {ex}")
        print(f"[ERROR] Traceback:\n{traceback.format_exc()}")
        raise


@app.post("/api/write/time-range-apply")
async def tr_apply(data: sch.TimeRangeApplyRequest,
                   cu: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    name = validate_identifier(data.name, "Time-range name")
    if not data.commands:
        raise ValidationError("There are no commands to apply.")
    for c in data.commands:
        check_cli_safe(c, "Command")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    existing_ranges = {r["name"].lower(): r
                       for r in await asyncio.to_thread(svc.get_time_ranges, t, cu.username)}
    previous = existing_ranges.get(name.lower())
    was_new = previous is None

    # If editing an existing time range, get the old config for undo and delete it first
    old_config_lines = []
    commands_to_run = list(data.commands)

    if not was_new:
        # Get the existing configuration for undo
        try:
            out_config = await asyncio.to_thread(
                svc.show, t, cu.username, f"show running-config | section time-range {name}", timeout=30)
            old_config_lines = acl_parser.parse_time_range_config(
                out_config, previous["name"])
        except Exception:
            old_config_lines = []
        if not old_config_lines:
            old_config_lines = [f"time-range {previous['name']}"] + [
                re.sub(r"\s+(?:\*?\s*)?[\[(]?(?:active|inactive)[\])]?\s*$",
                       "", entry, flags=re.IGNORECASE).strip()
                for entry in previous.get("entries", [])
            ]

        # Prepend delete command to remove old entries, then recreate with new ones
        commands_to_run = [f"no time-range {name}"] + commands_to_run

    ok, out, err = await asyncio.to_thread(
        svc.configure, t, cu.username, commands_to_run, timeout=45)
    if not ok:
        action = "update" if not was_new else "apply"
        audit.log_error(db, cu.username,
                        f"Failed to {action} time-range '{name}' on {t.label}",
                        f"Commands: {' ; '.join(commands_to_run)}\nProblem: {err}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the time-range.",
                "output": out, "undo_commands": []}

    # Set undo commands
    if was_new:
        undo = [f"no time-range {name}"]
        undo_label = f"delete time-range {name}"
    else:
        # For edits, undo means restoring the old configuration
        undo = old_config_lines if old_config_lines else [f"no time-range {name}"]
        undo_label = f"restore previous time-range {name}"

    action = "Edited" if not was_new else "Applied"
    audit.log_success(db, cu.username,
                      f"{action} time-range '{name}' on {t.label}",
                      f"Commands: {' ; '.join(commands_to_run)}",
                      undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_TIME_RANGE)

    message = f"Time-range '{name}' {'updated' if not was_new else 'applied'} on {t.label}. " \
              f"Running-config only — use Save Config when ready."

    return {"success": True,
            "message": message,
            "output": out, "undo_commands": undo, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/time-range-delete")
async def tr_delete(data: sch.TimeRangeDeleteRequest,
                    cu: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    name = validate_identifier(data.name, "Time-range name")
    
    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    # Get the existing time range configuration for undo
    existing_ranges = {r["name"].lower(): r
                       for r in await asyncio.to_thread(svc.get_time_ranges, t, cu.username)}
    existing = existing_ranges.get(name.lower())
    if not existing:
        return {"success": False,
                "message": f"Time-range '{name}' not found on {t.label}.",
                "output": "", "undo_commands": []}

    # Get the full configuration to reconstruct it for undo
    try:
        out_config = await asyncio.to_thread(
            svc.show, t, cu.username, f"show running-config | section time-range {name}", timeout=30)
        undo_commands = acl_parser.parse_time_range_config(
            out_config, existing["name"])
    except Exception:
        undo_commands = []
    if not undo_commands:
        undo_commands = [f"time-range {existing['name']}"] + [
            re.sub(r"\s+(?:\*?\s*)?[\[(]?(?:active|inactive)[\])]?\s*$",
                   "", entry, flags=re.IGNORECASE).strip()
            for entry in existing.get("entries", [])
        ]

    # Execute delete command
    delete_cmd = [f"no time-range {name}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, delete_cmd, timeout=45)

    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to delete time-range '{name}' on {t.label}",
                        f"Command: {delete_cmd[0]}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the delete command.",
                "output": out, "undo_commands": []}
    undo_label = f"restore time-range {name}"
    audit.log_success(db, cu.username,
                      f"Deleted time-range '{name}' on {t.label}",
                      f"Command: {delete_cmd[0]}",
                      undo_commands=undo_commands, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_TIME_RANGE)

    return {"success": True,
            "message": f"Time-range '{name}' deleted from {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out,
            "undo_commands": undo_commands,
            "switch_id": t.id,
            "undo_label": undo_label}


def _validate_group_ref(t: svc.SwitchTarget, username: str, name: str,
                        expected_kind: str, field: str) -> Dict[str, Any]:
    """Ensure a nested 'group-object NAME' reference exists as the required kind."""
    inventory = {g["name"].lower(): g for g in svc.get_object_groups(t, username)}
    item = inventory.get(name.lower())
    if not item:
        raise ValidationError(f"{field} object group '{name}' does not exist on {t.label}.")
    if item["kind"] != expected_kind:
        raise ValidationError(
            f"Object group '{name}' is a {item['kind']} group, not a "
            f"{expected_kind} group required by {field.lower()}.")
    return item


def _og_member_line(t: svc.SwitchTarget, username: str, kind: str,
                    member: "sch.ObjectGroupMemberInput") -> str:
    """Validate one member row and build its platform-correct config line."""
    is_nxos = t.is_nexus
    if kind == "address":
        if member.protocol or member.port:
            raise ValidationError("Address group rows cannot include a protocol or port.")
        if member.group_ref:
            if is_nxos:
                raise ValidationError(
                    f"A row nests object-group '{member.group_ref}', which is only "
                    f"supported on IOS. {t.label} is NX-OS.")
            name = validate_object_group_name(member.group_ref, "Nested group")
            _validate_group_ref(t, username, name, "address", "Nested group")
            return rule_generator.object_group_address_member(
                group_ref=name, switch_type=t.type)
        if not member.prefix:
            raise ValidationError("Each address row needs a prefix or a nested object-group.")
        prefix = (validate_prefix(member.prefix, "Prefix") if is_nxos
                  else validate_object_group_ip(member.prefix, "Address"))
        return rule_generator.object_group_address_member(prefix=prefix, switch_type=t.type)

    # kind == "port"
    if member.group_ref:
        if is_nxos:
            raise ValidationError(
                f"A row nests object-group '{member.group_ref}', which is only "
                f"supported on IOS. {t.label} is NX-OS.")
        name = validate_object_group_name(member.group_ref, "Nested group")
        _validate_group_ref(t, username, name, "port", "Nested group")
        return rule_generator.object_group_port_member(group_ref=name, switch_type=t.type)
    if not member.port:
        raise ValidationError("Each port row needs a port or a nested object-group.")
    if is_nxos:
        if member.protocol:
            raise ValidationError(
                f"A row sets a protocol, which is not supported on NX-OS port "
                f"groups ({t.label}).")
        port = validate_port_only(member.port, "Port")
        protocol = None
    else:
        if not member.protocol:
            raise ValidationError(
                "Each IOS port row needs a protocol (TCP, UDP, or TCP-UDP).")
        protocol = validate_protocol_only(member.protocol)
        port = validate_ios_port_spec(member.port, protocol, "Port")
    return rule_generator.object_group_port_member(
        protocol=protocol, port=port, switch_type=t.type)


def _og_delete_target(t: svc.SwitchTarget, stored_member_line: str) -> str:
    """
    Return the argument for 'no <target>' inside an object-group context.
    NX-OS members are stored with a leading sequence number ('10 host 1.2.3.4') —
    deleting by that sequence number is the reliable form there. IOS members carry
    no sequence number, so the member text itself is the delete target.
    """
    m = re.match(r"^(\d+)\s+", stored_member_line.strip())
    if t.is_nexus and m:
        return m.group(1)
    return rule_generator.strip_og_seq(stored_member_line)


@app.post("/api/write/object-group-preview")
async def og_preview(data: sch.ObjectGroupCreatePreviewRequest,
                     cu: User = Depends(require_admin),
                     db: Session = Depends(get_db)):
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")
    if not data.members:
        raise ValidationError("Add at least one rule to create an object group.")

    targets = svc.resolve_targets(data.switch_ids, cu.username, db, require_write=True)

    def work(t):
        existing = {g["name"].lower(): g for g in svc.get_object_groups(t, cu.username)}
        if name.lower() in existing:
            found = existing[name.lower()]
            raise ValidationError(
                f"Object group '{name}' already exists on {t.label} as a "
                f"{found['kind']} group. Use its Add Member action instead of "
                f"creating a new group.")
        header = rule_generator.object_group_header(name, kind, t.type)
        lines = [_og_member_line(t, cu.username, kind, m) for m in data.members]
        commands = [header] + [f" {line}" for line in lines]
        return {"commands": commands}

    return {"name": name, "kind": kind,
            "switches": await _per_switch_async(targets, work),
            "message": "Review the commands below, then apply."}


@app.post("/api/write/object-group-apply")
async def og_apply(data: sch.ObjectGroupCreateApplyRequest,
                   cu: User = Depends(require_admin),
                   db: Session = Depends(get_db)):
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")
    if not data.commands:
        raise ValidationError("There are no commands to apply.")
    for c in data.commands:
        check_cli_safe(c, "Command")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    existing = {g["name"].lower(): g for g in
                await asyncio.to_thread(svc.get_object_groups, t, cu.username)}
    if name.lower() in existing:
        found = existing[name.lower()]
        return {"success": False,
                "message": f"Object group '{name}' already exists on {t.label} as a "
                           f"{found['kind']} group. Refresh and use Add Member instead.",
                "output": "", "undo_commands": []}

    header = rule_generator.object_group_header(name, kind, t.type)
    ok, out, err = await asyncio.to_thread(
        svc.configure, t, cu.username, data.commands, timeout=45)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to create object group '{name}' on {t.label}",
                        f"Commands: {' ; '.join(data.commands)}\nProblem: {err}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the object group.",
                "output": out, "undo_commands": []}

    verify = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    created = next((g for g in verify if g["name"].lower() == name.lower()
                    and g["kind"] == kind), None)
    if not created:
        _ok, rollback_out, _err = await asyncio.to_thread(
            svc.configure, t, cu.username, [f"no {header}"])
        message = ("The switch did not confirm the new object group. It was "
                   "rolled back; review the raw switch output below.")
        combined = f"Configuration response:\n{out}\n\nRollback response:\n{rollback_out}"
        audit.log_error(db, cu.username,
                        f"Could not verify object group '{name}' on {t.label}",
                        f"Commands: {' ; '.join(data.commands)}\n{combined}",
                        event_type=db_models.EV_OBJECT_GROUP)
        return {"success": False, "message": message, "output": combined,
                "undo_commands": []}
    undo = [f"no {header}"]
    undo_label = f"delete object group {name}"
    audit.log_success(db, cu.username,
                      f"Created {kind} object group '{name}' on {t.label}",
                      f"Commands: {' ; '.join(data.commands)}",
                      undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_OBJECT_GROUP)
    return {"success": True,
            "message": f"Object group '{name}' created on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/object-group-member-add")
async def og_member_add(data: sch.ObjectGroupMemberAddRequest,
                        cu: User = Depends(require_admin),
                        db: Session = Depends(get_db)):
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    groups = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    current = next((g for g in groups if g["name"].lower() == name.lower()), None)
    if not current:
        raise ValidationError(f"Object group '{name}' was not found on {t.label}.")
    if current["kind"] != kind:
        raise ValidationError(
            f"Object group '{name}' is a {current['kind']} group on {t.label}, not {kind}.")

    member_line = await asyncio.to_thread(_og_member_line, t, cu.username, kind, data.member)
    header = rule_generator.object_group_header(name, kind, t.type)
    cmds = [header, f" {member_line}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to add a member to object group '{name}' on {t.label}",
                        f"Member: {member_line}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False, "message": err or "The switch rejected the member.",
                "output": out, "undo_commands": []}

    verify = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    verify_group = next((g for g in verify if g["name"].lower() == name.lower()), None)
    matched_full = next((m for m in (verify_group["members"] if verify_group else [])
                        if rule_generator.strip_og_seq(m) == member_line), None)
    if not matched_full:
        _ok, rollback_out, _err = await asyncio.to_thread(
            svc.configure, t, cu.username, [header, f" no {member_line}"])
        message = ("The switch did not confirm the new member. An attempt was "
                   "made to remove it; review the raw switch output below.")
        combined = f"Configuration response:\n{out}\n\nRollback response:\n{rollback_out}"
        audit.log_error(db, cu.username,
                        f"Could not verify member of object group '{name}' on {t.label}",
                        f"Member: {member_line}\n{combined}",
                        event_type=db_models.EV_OBJECT_GROUP)
        return {"success": False, "message": message, "output": combined,
                "undo_commands": []}

    delete_target = _og_delete_target(t, matched_full)
    undo = [header, f" no {delete_target}"]
    undo_label = f"remove that member from {name}"
    audit.log_success(db, cu.username,
                      f"Added a member to object group '{name}' on {t.label}",
                      f"Member: {member_line}\nCommands: {' ; '.join(cmds)}",
                      undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_OBJECT_GROUP)
    return {"success": True,
            "message": f"Member added to '{name}' on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/object-group-member-delete")
async def og_member_delete(data: sch.ObjectGroupMemberDeleteRequest,
                           cu: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")
    member_line = validate_object_group_member_line(data.member_line, "Member")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    groups = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    current = next((g for g in groups if g["name"].lower() == name.lower()), None)
    if not current or current["kind"] != kind:
        raise ValidationError(f"Object group '{name}' ({kind}) was not found on {t.label}.")
    original = next((m for m in current["members"] if m.strip() == member_line.strip()), None)
    if original is None:
        raise ValidationError(
            f"That member was not found in '{name}' on {t.label}. It may already "
            f"be gone — refresh the object groups.")

    header = rule_generator.object_group_header(name, kind, t.type)
    delete_target = _og_delete_target(t, original)
    cmds = [header, f" no {delete_target}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to delete a member from object group '{name}' on {t.label}",
                        f"Member: {original}\nProblem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False, "message": err or "The switch rejected the change.",
                "output": out, "undo_commands": []}
    undo = [header, f" {rule_generator.strip_og_seq(original)}"]
    undo_label = f"restore that member in {name}"
    audit.log_warn(db, cu.username,
                   f"Deleted a member from object group '{name}' on {t.label}",
                   f"Removed: {original}\nCommands: {' ; '.join(cmds)}",
                   undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                   event_type=db_models.EV_OBJECT_GROUP)
    return {"success": True,
            "message": f"Member removed from '{name}' on {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/object-group-member-edit")
async def og_member_edit(data: sch.ObjectGroupMemberEditRequest,
                         cu: User = Depends(require_admin),
                         db: Session = Depends(get_db)):
    """Replace one object-group member, restoring the original if anything fails."""
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")
    requested_original = validate_object_group_member_line(
        data.original_member, "Original member")
    replacement = validate_object_group_member_line(data.new_member, "New member")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    groups = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    current = next((g for g in groups if g["name"].lower() == name.lower()), None)
    if not current or current["kind"] != kind:
        raise ValidationError(f"Object group '{name}' ({kind}) was not found on {t.label}.")
    original = next((m for m in current["members"]
                     if m.strip() == requested_original.strip()), None)
    if original is None:
        raise ValidationError(
            f"That member was not found in '{name}' on {t.label}. It may already "
            f"have changed — refresh the object groups.")
    if rule_generator.strip_og_seq(original) == replacement:
        return {"success": True, "changed": False,
                "message": "The replacement is identical to the existing member.",
                "output": "", "undo_commands": []}

    header = rule_generator.object_group_header(name, kind, t.type)
    delete_target = _og_delete_target(t, original)
    commands = [header, f" no {delete_target}", f" {replacement}"]

    def restore_original() -> tuple:
        rollback = [header, f" no {replacement}", f" {rule_generator.strip_og_seq(original)}"]
        rollback_ok, rollback_output, rollback_error = svc.configure(
            t, cu.username, rollback, timeout=45)
        try:
            verify_groups = svc.get_object_groups(t, cu.username)
            vg = next((g for g in verify_groups if g["name"].lower() == name.lower()), None)
            restored = bool(vg) and any(
                rule_generator.strip_og_seq(m) == rule_generator.strip_og_seq(original)
                for m in vg["members"])
        except ssh_manager.SSHError:
            restored = False
        return rollback_output, bool(rollback_ok and not rollback_error and restored)

    ok, output, error = await asyncio.to_thread(
        svc.configure, t, cu.username, commands, timeout=45)
    if not ok:
        rollback_output, restored = await asyncio.to_thread(restore_original)
        combined = (f"Replacement response:\n{output}\n\n"
                    f"Original-member restore response:\n{rollback_output}")
        restore_message = ("The original member was restored." if restored else
                           "Restoration was attempted but could not be confirmed; "
                           "review the switch output immediately.")
        audit.log_error(
            db, cu.username,
            f"Failed to edit a member of object group '{name}' on {t.label}",
            f"Original: {original}\nReplacement: {replacement}\n"
            f"Problem: {error}\n\n{combined}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": (error or "The switch rejected the replacement member.")
                           + f" {restore_message}",
                "output": combined, "undo_commands": []}

    try:
        verify_groups = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
        vg = next((g for g in verify_groups if g["name"].lower() == name.lower()), None)
        replacement_present = bool(vg) and any(
            rule_generator.strip_og_seq(m) == replacement for m in vg["members"])
        original_still_present = bool(vg) and any(
            rule_generator.strip_og_seq(m) == rule_generator.strip_og_seq(original)
            for m in vg["members"])
    except ssh_manager.SSHError as exc:
        replacement_present, original_still_present = False, False
    if not replacement_present or original_still_present:
        rollback_output, restored = await asyncio.to_thread(restore_original)
        combined = (f"Replacement response:\n{output}\n\n"
                    f"Original-member restore response:\n{rollback_output}")
        message = ("The switch did not confirm the replacement member. "
                   + ("The original member was restored." if restored else
                      "Restoration was attempted but could not be confirmed; "
                      "review the switch output immediately."))
        audit.log_error(
            db, cu.username,
            f"Could not verify edited member of object group '{name}' on {t.label}",
            f"Original: {original}\nReplacement: {replacement}\n\n{combined}",
                        event_type=db_models.EV_OBJECT_GROUP)
        return {"success": False, "message": message,
                "output": combined, "undo_commands": []}
    undo = [header, f" no {replacement}", f" {rule_generator.strip_og_seq(original)}"]
    undo_label = f"restore that member in {name}"
    audit.log_success(
        db, cu.username, f"Edited a member of object group '{name}' on {t.label}",
        f"Original: {original}\nReplacement: {replacement}",
        undo_commands=undo, undo_label=undo_label, switch_id=t.id,
                      event_type=db_models.EV_OBJECT_GROUP)
    return {"success": True, "changed": True,
            "message": f"Member replaced in '{name}' on {t.label}. "
                       "Running-config only — use Save Config when ready.",
            "output": output, "undo_commands": undo, "undo_label": undo_label,
            "switch_id": t.id}


@app.post("/api/write/object-group-delete")
async def og_delete(data: sch.ObjectGroupDeleteRequest,
                    cu: User = Depends(require_admin),
                    db: Session = Depends(get_db)):
    name = validate_object_group_name(data.name, "Object group name")
    kind = (data.kind or "").strip().lower()
    if kind not in ("address", "port"):
        raise ValidationError("Group kind must be 'address' or 'port'.")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)

    groups = await asyncio.to_thread(svc.get_object_groups, t, cu.username)
    current = next((g for g in groups if g["name"].lower() == name.lower()), None)
    if not current or current["kind"] != kind:
        return {"success": False,
                "message": f"Object group '{name}' ({kind}) was not found on {t.label}. "
                           f"It may already be gone — refresh the object groups.",
                "output": "", "undo_commands": []}

    header = rule_generator.object_group_header(name, kind, t.type)
    undo_commands = [header] + [f" {rule_generator.strip_og_seq(m)}"
                                for m in current["members"]]
    cmds = [f"no {header}"]
    ok, out, err = await asyncio.to_thread(svc.configure, t, cu.username, cmds)
    if not ok:
        audit.log_error(db, cu.username,
                        f"Failed to delete object group '{name}' on {t.label}",
                        f"Problem: {err}\n\nSwitch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the delete command.",
                "output": out, "undo_commands": []}
    undo_label = f"restore object group {name}"
    audit.log_warn(db, cu.username,
                   f"Deleted object group '{name}' on {t.label}",
                   f"Members removed: {len(current['members'])}\nCommand: {cmds[0]}",
                   undo_commands=undo_commands, undo_label=undo_label, switch_id=t.id,
                   event_type=db_models.EV_OBJECT_GROUP)
    return {"success": True,
            "message": f"Object group '{name}' deleted from {t.label}. "
                       f"Running-config only — use Save Config when ready.",
            "output": out, "undo_commands": undo_commands, "switch_id": t.id,
            "undo_label": undo_label}


@app.post("/api/write/undo")
async def undo(data: sch.UndoRequest, cu: User = Depends(require_admin),
               db: Session = Depends(get_db)):
    """Run a previously supplied set of undo commands on one switch."""
    if not data.commands:
        raise ValidationError("There is nothing to undo.")
    for c in data.commands:
        check_cli_safe(c, "Undo command")

    sw, pw, enable_pw = get_switch_and_password(data.switch_id, cu.username, None, db)
    ssh_username = sw.ssh_username or cu.username
    t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)
    label = check_cli_safe(data.label or "change", "Label")

    ok, out, err = await asyncio.to_thread(
        svc.configure, t, cu.username, list(data.commands), timeout=45)

    if not ok:
        audit.log_error(db, cu.username, f"Undo failed on {t.label}",
                        f"Attempted to {label}\nCommands: "
                        f"{' ; '.join(data.commands)}\nProblem: {err}\n\n"
                        f"Switch output:\n{out}",
                        event_type=db_models.EV_WRITE_FAILED)
        return {"success": False,
                "message": err or "The switch rejected the undo commands.",
                "output": out}

    # Section-level undo must consume the same audit entry that supplies the
    # Logs page Undo button. Match the exact serialized commands and newest
    # entry so identical historical changes are not all cleared at once.
    undo_json = json.dumps(list(data.commands))
    original_log = db.query(AuditLog).filter(
        AuditLog.switch_id == t.id,
        AuditLog.username == cu.username,
        AuditLog.undo_commands == undo_json,
    ).order_by(AuditLog.timestamp.desc(), AuditLog.id.desc()).first()
    latest_save = _latest_switch_log(
        db, t.id, cu.username, "Saved configuration on ")
    post_save_undo = (
        latest_save is not None and
        (original_log is None or _log_is_newer(latest_save, original_log)))
    if original_log:
        original_log.undo_commands = None
        original_log.undo_label = None
        db.commit()

    # Normally an undo returns running-config to its prior clean state. If the
    # original action was already consumed by Save Config, however, this undo
    # changes running-config *after* that checkpoint and is itself unsaved.
    audit.log_warn(
        db, cu.username,
        (f"Undid a saved change on {t.label}" if post_save_undo
         else f"Undid a change on {t.label}"),
        f"Undo action: {label}\nCommands: {' ; '.join(data.commands)}",
        switch_id=t.id,
                   event_type=db_models.EV_UNDO)
    message = f"Reverted on {t.label} ({label})."
    if post_save_undo:
        message += " Running-config now has UNSAVED changes."
    return {"success": True,
            "message": message,
            "output": out, "switch_id": t.id}


@app.post("/api/write/save-config")
async def save_config(data: sch.SaveConfigRequest,
                      cu: User = Depends(require_admin),
                      db: Session = Depends(get_db)):
    targets = svc.resolve_targets(data.switch_ids, cu.username, db)

    def save_one(t):
        """Runs in a worker thread; must not touch the request's session."""
        try:
            out = svc.run_with_confirm(
                t, cu.username, "copy running-config startup-config",
                timeout=60, enable_password=t.enable_password)
        except ssh_manager.SSHError as e:
            return {"success": False, "message": str(e), "output": "",
                    "log": ("error", f"SSH error while saving config on {t.label}",
                            str(e), None)}
        err = ssh_manager.detect_switch_error(out)
        if err:
            return {"success": False, "message": err, "output": out,
                    "log": ("error", f"Failed to save config on {t.label}",
                            f"{err}\n\nSwitch output:\n{out}",
                            db_models.EV_WRITE_FAILED)}
        return {"success": True, "message": "Configuration saved.", "output": out,
                "log": ("success", f"Saved configuration on {t.label}",
                        "copy running-config startup-config",
                        db_models.EV_CONFIG_SAVE)}

    # Both switches of a VPC pair save at the same time rather than one after
    # the other. Auditing happens back here, on the request's own session.
    loop = asyncio.get_event_loop()
    outcomes = await asyncio.gather(*[
        loop.run_in_executor(_switch_executor, save_one, t) for t in targets])

    results = []
    for t, outcome in zip(targets, outcomes):
        level, message, detail, event = outcome.pop("log")
        writer = audit.log_success if level == "success" else audit.log_error
        writer(db, cu.username, message, detail, switch_id=t.id,
               event_type=event)
        results.append({"switch_id": t.id, "switch_name": t.label, **outcome})

    ok_all = all(r["success"] for r in results)
    msg = ("Configuration saved." if ok_all
           else "Some switches could not be saved.")
    return {"success": ok_all, "message": msg, "results": results}


@app.post("/api/write/bulk-save-config")
async def bulk_save_config(data: sch.SaveConfigRequest,
                           cu: User = Depends(require_admin),
                           db: Session = Depends(get_db)):
    """Save configuration on multiple switches without VPC pair restriction. Runs in parallel."""
    if not data.switch_ids:
        raise HTTPException(400, "No switches specified.")
    
    import asyncio
    import threading
    from concurrent.futures import ThreadPoolExecutor

    def save_one_switch(switch_id: int):
        """Save config for a single switch - runs in thread."""
        worker_db = SessionLocal()
        try:
            sw, pw, enable_pw = get_switch_and_password(
                switch_id, cu.username, None, worker_db)
            ssh_username = sw.ssh_username or cu.username
            t = svc.SwitchTarget(sw, pw, ssh_username, enable_pw)
            
            # Use run_with_confirm for copy command which requires confirmation
            out = svc.run_with_confirm(t, cu.username, "copy running-config startup-config",
                                       timeout=60, enable_password=t.enable_password)
            
            err = ssh_manager.detect_switch_error(out)
            if err:
                audit.log_error(worker_db, cu.username,
                                f"Failed to save config on {t.label}",
                                f"{err}\n\nSwitch output:\n{out}",
                                switch_id=t.id,
                                event_type=db_models.EV_WRITE_FAILED)
                return {"switch_id": t.id, "switch_name": t.label,
                        "success": False, "message": err, "output": out}
            else:
                audit.log_success(worker_db, cu.username,
                                  f"Saved configuration on {t.label}",
                                  "copy running-config startup-config",
                                  switch_id=t.id,
                                  event_type=db_models.EV_CONFIG_SAVE)
                return {"switch_id": t.id, "switch_name": t.label,
                        "success": True, "message": "Configuration saved.", "output": out}
        except ssh_manager.SSHError as e:
            audit.log_error(worker_db, cu.username,
                            f"SSH error while saving config on switch {switch_id}", str(e),
                            switch_id=switch_id)
            return {"switch_id": switch_id, "switch_name": f"Switch {switch_id}",
                    "success": False, "message": str(e), "output": ""}
        except Exception as e:
            audit.log_error(
                worker_db, cu.username,
                f"Failed to save config on switch {switch_id}", str(e),
                switch_id=switch_id,
                            event_type=db_models.EV_WRITE_FAILED)
            return {"switch_id": switch_id, "switch_name": f"Switch {switch_id}",
                    "success": False, "message": str(e), "output": ""}
        finally:
            worker_db.close()
    
    # Run saves in parallel using thread pool
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [loop.run_in_executor(executor, save_one_switch, sid) 
                   for sid in data.switch_ids]
        results = await asyncio.gather(*futures)

    ok = all(r["success"] for r in results)
    saved = [r["switch_name"] for r in results if r["success"]]
    failed = [r["switch_name"] for r in results if not r["success"]]
    if ok:
        msg = f"Configuration saved on {len(saved)} switch{'es' if len(saved) != 1 else ''}: {', '.join(saved)}."
    elif saved:
        msg = (f"Saved on {', '.join(saved)} but failed on "
               f"{', '.join(failed)}. See details below.")
    else:
        msg = f"Could not save configuration on {', '.join(failed)}."
    return {"success": ok, "message": msg, "results": results}


# ═══════════════════════ HEALTH ═══════════════════════

@app.get("/api/health")
async def health():
    """Liveness for systemd, a proxy, or a monitor. Deliberately unauthenticated
    and deliberately empty of detail: anything that can reach the port can read
    this, so it says the process is up and answers nothing about the estate.
    A database round trip is included -- a process that cannot reach its own
    database is not healthy, however well it answers HTTP."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(503, "Database unavailable.")
    finally:
        db.close()
    return {"status": "ok"}


# ═══════════════════════ STATIC / SPA ═══════════════════════

FRONTEND_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "frontend"))


if os.path.isdir(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/")
    async def index():
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))

    @app.get("/{path:path}")
    async def spa(path: str):
        if path.startswith("api/"):
            raise HTTPException(404, "Unknown API endpoint.")
        full = os.path.normpath(os.path.join(FRONTEND_DIR, path))
        if full.startswith(FRONTEND_DIR) and os.path.isfile(full):
            return FileResponse(full)
        return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))


def _guard_against_orphaning_credentials():
    """
    Refuse to generate a new key while unreadable credentials are stored.

    Generating a key is only safe when everything on disk can still be read —
    either with the current key or with the old published one. If neither
    works, some previous key is missing (a lost or unreadable .env), and
    rotating again would make those passwords unrecoverable rather than
    merely unreadable. Better to stop and say so.
    """
    if not crypto.is_insecure_secret(settings.SECRET_KEY):
        return                      # A real key is loaded; nothing to rotate.
    db = SessionLocal()
    try:
        for row in db.query(Switch).filter(
                (Switch.saved_password.isnot(None)) |
                (Switch.saved_enable_password.isnot(None))).all():
            for token in (row.saved_password, row.saved_enable_password):
                if not token:
                    continue
                try:
                    crypto.decrypt_password(settings.SECRET_KEY, token)
                except Exception:
                    raise RuntimeError(
                        "Stored switch passwords cannot be read with the "
                        f"current SECRET_KEY, and none is set. {crypto.ENV_FILE} "
                        "is probably missing or was replaced. Restore it "
                        "before starting, or clear the saved passwords and "
                        "re-enter them — generating a new key now would make "
                        "them permanently unrecoverable.")
    except Exception:
        raise
    finally:
        db.close()


def _reencrypt_stored_credentials(db: Session) -> int:
    """
    Move stored switch passwords onto the current key.

    Values written under the old scheme stay readable through the fallback in
    crypto.decrypt_password, so this can run at any point after the key
    changes — but until it does, they remain encrypted with a key that was
    published in the repository.
    """
    from config import settings
    moved = 0
    for row in db.query(Switch).filter(
            (Switch.saved_password.isnot(None)) |
            (Switch.saved_enable_password.isnot(None))).all():
        for field in ("saved_password", "saved_enable_password"):
            token = getattr(row, field)
            if not token or not crypto.is_legacy_ciphertext(settings.SECRET_KEY, token):
                continue
            try:
                plain = crypto.decrypt_password(settings.SECRET_KEY, token)
            except Exception:
                # Unreadable under either key: leave it alone rather than
                # destroy it. The switch will ask for its password again.
                continue
            setattr(row, field,
                    crypto.encrypt_password(settings.SECRET_KEY, plain))
            moved += 1
    if moved:
        db.commit()
    return moved


@app.on_event("startup")
async def _startup():
    # Bring the schema up to date first. The credential guard below reads the
    # switches table through the ORM, so every mapped column has to exist
    # before it runs — on a database file older than the newest column it
    # would otherwise fail with "no such column" and the app would not start.
    # Nothing in init_db touches a credential, so it is safe ahead of the guard.
    init_db()
    # Before anything reads or writes a credential: replace the placeholder
    # secret that shipped in the repository, then move anything encrypted
    # under it onto the new key.
    _guard_against_orphaning_credentials()
    rotated = crypto.ensure_secret_key(settings)
    if rotated:
        print("[SECURITY] Generated a new SECRET_KEY and saved it to .env. "
              "Existing sign-in sessions are now invalid.")
    db = SessionLocal()
    try:
        moved = _reencrypt_stored_credentials(db)
        if moved:
            print(f"[SECURITY] Re-encrypted {moved} stored credential(s) "
                  "with the new key.")
        ensure_admin_exists(db)
        if uses_default_admin_password(db):
            # Named, never quoted: the console must not hand out a working
            # password to whoever can read it.
            print("[SECURITY] The 'admin' account is still using a password "
                  "that appears in this project's documentation. Change it.")
    finally:
        db.close()
    asyncio.create_task(_log_retention_sweep())


LOG_RETENTION_CHECK_SECONDS = 6 * 3600


async def _log_retention_sweep():
    """Runs for the life of the process, checking every 6 hours whether
    scheduled auto-delete is enabled and, if so, sweeping old logs. A 6-hour
    cadence is frequent enough that even the shortest configurable period
    (1 month) is never overshot by more than a few hours, without checking
    so often it's wasteful. Deleting is idempotent — a missed or doubled
    check never double-deletes — so no locking is needed."""
    while True:
        db = SessionLocal()
        try:
            log_retention.run_scheduled_cleanup(db)
        except Exception as e:
            print(f"[LOG RETENTION] Sweep failed: {e}")
            db.rollback()
        finally:
            db.close()
        await asyncio.sleep(LOG_RETENTION_CHECK_SECONDS)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
