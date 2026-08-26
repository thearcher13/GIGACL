# GIGACL — Project Documentation

Living reference for the GIGACL platform. Every feature, rule and design
decision is recorded here section by section so this file can be updated in
place as the project changes.

| | |
|---|---|
| **Version** | 3.7 |
| **Last updated** | 2026-08-26 |
| **Stack** | Python 3.10+ (developed on 3.13) · FastAPI · SQLAlchemy · SQLite · Netmiko/Paramiko · vanilla JS/CSS |
| **Default account** | `admin` / `admin` (role: super admin) — **change it at first sign-in**. It is deliberately weak, is never printed by the server, and fails the app's own password rules. |
| **Install** | `./setup.sh` (Linux/macOS) or `setup.ps1` (Windows) |
| **Start command** | `./start.sh` / `start.bat` — serves on `http://0.0.0.0:8000` |
| **Tests** | `cd backend && ../venv/bin/python -m unittest discover -s . -p "test_*.py"` — 788 tests, 32 modules, no pytest |
| **Deployment** | See `README.md` for the systemd unit, the nginx config and the production checklist. `PROJECT-OVERVIEW.md` is the feature write-up. |

### How to maintain this document
- One section per subsystem. Add a new numbered section for a new subsystem.
- Every table row is a discrete, testable behaviour. Add rows; avoid rewriting.
- When behaviour changes, edit the row rather than appending a note elsewhere.
  This file describes what the code does now; it is not a history.
- §16 must list every route registered in `main.py`. The check is mechanical:
  compare `grep -oE '@app\.(get|post|put|delete|websocket)\("[^"]+"' backend/main.py`
  against the paths in that section. It has drifted before.

---


## Table of Contents

| § | Section |
|---|---|
| 1 | [Purpose & Constraints](#1-purpose--constraints) |
| 2 | [Architecture & File Map](#2-architecture--file-map) |
| 3 | [Data Model](#3-data-model) |
| 4 | [Authentication, Roles & Lockout](#4-authentication-roles--lockout) |
| 5 | [User Management](#5-user-management) |
| 6 | [Switch Inventory](#6-switch-inventory) |
| 7 | [Locations (Site Labels)](#7-locations-site-labels) |
| 8 | [VPC Pairing & Multi-Switch Selection](#8-vpc-pairing--multi-switch-selection) |
| 9 | [SSH Layer](#9-ssh-layer) |
| 10 | [ACL Parsing & Directional Logic](#10-acl-parsing--directional-logic) |
| 11 | [Read Features](#11-read-features) |
| 12 | [Write Features](#12-write-features) |
| 13 | [Audit Logging](#13-audit-logging) |
| 14 | [Validation & Security](#14-validation--security) |
| 15 | [Frontend & UX](#15-frontend--ux) |
| 16 | [API Reference](#16-api-reference) |

---

## 1. Purpose & Constraints

A web application for querying and managing IP access lists on Cisco switches
over SSH.

| Constraint | Status | Notes |
|---|---|---|
| No AI / ML / LLM anywhere in the product | Enforced | All logic is deterministic and rule-based. No model calls, no inference, no external AI services. |
| Traditional rule-based logic only | Enforced | ACL evaluation is explicit parsing plus `ipaddress` set maths. |
| SSH to switches | Netmiko | Chosen over raw paramiko for legacy Cisco algorithm negotiation, enable mode and paging. |
| Local database | SQLite | `backend/giga_acl.db`, created and migrated automatically. |
| No scope creep | Observed | Only requested features are implemented. |
| Permit rules only via the UI | Enforced | Deny rules are rejected in the browser **and** at the API. |
| No automatic config save | Enforced | `copy running-config startup-config` runs only from the Save Config button. |

---

## 2. Architecture & File Map

Route handlers are registered directly on the `app` object. FastAPI 0.140 has a
lazy-resolution defect in `include_router` that silently dropped all but the
first route from any router carrying a prefix; registering directly avoids it
entirely. This is intentional — do not refactor back to routers without
verifying that bug is gone.

### Backend — `backend/`

| File | Responsibility |
|---|---|
| `main.py` | FastAPI app, middleware, exception handlers, all route handlers. Handlers stay thin and delegate to services. |
| `config.py` | Settings: secret key, token lifetime, database URL. Reads `.env` by absolute path — `start.sh` runs from `backend/`, so a relative lookup missed it. |
| `crypto.py` | Secret-key generation and persistence; HKDF derivation of separate signing and credential keys; credential encrypt/decrypt, including reading the legacy scheme. |
| `database.py` | SQLAlchemy models, role/type/site constants, `init_db()`, additive SQLite migrations, retired-theme remapping. |
| `schemas.py` | Pydantic request and response models. |
| `auth.py` | Password hashing (bcrypt), JWT issue/verify, role dependencies, password policy, token revocation, presence tracking, first-run seeding. |
| `lockout.py` | Brute-force lockout policy: counters, windows, lock/unlock, status serialisation. |
| `trusted_hosts.py` | Per-user IP/prefix allow lists: parsing, validation, membership. |
| `request_context.py` | Context variable holding the caller's address for audit and presence. |
| `audit.py` | Audit log writer. Never raises — a logging failure must not break an operation. |
| `log_retention.py` | Scheduled and manual deletion of old audit entries, with optional ZIP export first. |
| `validators.py` | All input validation and CLI-injection defence. Raises `ValidationError`. |
| `site_service.py` | Per-user location labels: add, delete, hide a built-in, validate, list. |
| `switch_utils.py` | Switch lookup scoped to the owner; SSH and enable password encryption. |
| `switch_service.py` | `SwitchTarget` wrapper, multi-select rules, command execution, per-request read cache, object-group and time-range fetch, the write-access guard. |
| `acl_service.py` | ACL evaluation orchestration, route resolution, object-group and time-range prefetch. |
| `acl_parser.py` | Pure parsing and matching: rules, routes, interfaces, object groups, time ranges, redundancy, summaries, dead schedules. |
| `acl_report.py` | The printable per-ACL report. |
| `ssh_manager.py` | Netmiko session cache, error classification, config/show execution. |
| `terminal_service.py` | Interactive SSH workspaces for the browser terminal: paramiko channels, per-user session registry, output pumps. |
| `health_collector.py` | The dashboard sweep: per-switch scan over SSH, stored as `switch_health` snapshots. |
| `tcam_parser.py` | TCAM utilisation parsing for the dashboard. |
| `rule_generator.py` | Builds Cisco CLI from validated input; sequence-number discovery. |
| `test_*.py` (32 files) | The suite. Plain `unittest`, no external runner. |

### Frontend — `frontend/`

| File | Responsibility |
|---|---|
| `index.html` | Single-page shell: login, sidebar, seventeen pages, fourteen modals. Static assets are cache-busted with `?v=NN`, bumped whenever one changes. |
| `app.js` | State, API client, validation mirror, custom select, renderers, all wiring. |
| `style.css` | Theme tokens for six themes, layout, components, animations. |
| `terminal.js` | The switch terminal window: xterm wiring, panes, docking, resize, synced input. |
| `logo.svg` | Brand mark. |
| `vendor/xterm/` | Vendored `xterm.js` 6.0.0 and its fit addon, with their licences. Not fetched from a CDN — this app is expected to run on isolated management networks. |

### Root

| File | Responsibility |
|---|---|
| `requirements.txt` | Pinned runtime dependencies. Direct dependencies only, so pip resolves platform-correct wheels. |
| `setup.sh` / `setup.ps1` | One-time install: interpreter check, venv, dependencies, `.env` at mode 600. Safe to re-run; never overwrites an existing `.env`. |
| `start.sh` / `start.bat` | Start uvicorn. Run setup themselves if it has not been run. Honour `HOST`, `PORT`, `PROXY`, `RELOAD`. Always `--workers 1`. |
| `stop.sh` / `stop.bat` | Stop the server, matching on the listening socket and confirming the process is ours before signalling it. |
| `.env.example` | Configuration template. `.env` itself is gitignored and holds the credential key. |
| `deploy/gigacl.service` | systemd unit: own account, `Restart=always`, hardening. |
| `deploy/nginx-gigacl.conf` | Reverse proxy for 80/443, with the websocket upgrade and forwarded-IP headers. |
| `README.md` | Install, first sign-in, service setup, port 80/443, backup, production checklist. |
| `PROJECT-OVERVIEW.md` | Feature write-up for a reader who has never seen the repository. |
| `DOCUMENTATION.md` | This file. |

### Process model

One worker, always — `--workers 1` in both start scripts and the systemd unit.
Netmiko sessions, terminal channels and the per-user connection pool live in
this process's memory, and SQLite takes one writer at a time. A second worker
would answer a share of the requests without any of that state.

### Request flow

```
Browser
  → validate in app.js (fast feedback, not trusted)
  → HTTP + Bearer JWT
  → ClientIPMiddleware      (park the caller's address for audit/presence)
  → main.py handler
      → auth dependency      (token, revocation cut-off, role, trusted hosts)
      → validators.py        (authoritative validation)
      → switch_service.py    (resolve targets, multi-select rules, write guard)
      → ssh_manager.py       (Netmiko, cached session, optional read cache)
      → acl_parser.py        (deterministic parsing / matching)
      → audit.py             (record the outcome, with the undo set)
  → JSON response
  → renderer in app.js
```

---

## 3. Data Model

Nine tables. Every column below exists on the model; the list is generated from
`__table__.columns`, not from memory.

### `users` (16)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `username` | varchar(64) unique | 2–64 chars: letters, digits, dot, dash, underscore. |
| `hashed_password` | varchar(128) | bcrypt with per-password salt. |
| `role` | varchar(20) | `user` · `admin` · `super_admin`. |
| `created_at` | datetime | |
| `failed_attempts` | int | Failures inside the current window. |
| `first_failed_at` | datetime | Start of the current failure window. |
| `locked_until` | datetime | Lock expiry; null when not locked. |
| `trusted_hosts` | text | Comma-separated IPs/prefixes. Empty means no restriction. |
| `switch_layout` | text | The user's own ordering of their switch cards. |
| `maga` | varchar(32) | The user's chosen unit label for rule counts. |
| `mega_visible` | bool | Whether that label is shown. |
| `theme` | varchar(32) | One of the six themes; retired ids are remapped on startup. |
| `tokens_valid_from` | datetime | Revocation cut-off. Tokens issued before this are refused. |
| `active_ips` | text | Addresses seen recently, for the presence marker. |
| `last_seen` | datetime | Drives "active users" and the in-use check before a role change. |

### `switches` (16)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `ip_address` | varchar(64) | Validated IPv4. |
| `hostname` | varchar(128) | Read from the switch on add; identity in the UI. |
| `switch_type` | varchar(32) | `ios` or `nexus`. |
| `site` | varchar(64) | Location label, or null for unassigned. |
| `owner_username` | varchar(64) idx | Every query is scoped by this. |
| `saved_password` | text | Encrypted SSH password. |
| `saved_enable_password` | text | Encrypted enable password, stored only when `use_enable` is set. |
| `use_enable` | bool | Send the enable password after login. |
| `ssh_username` | varchar(64) | SSH username for this switch; defaults to owner username. |
| `vpc_peer_id` | int | Bidirectional VPC link (Nexus only). |
| `pending_changes` | bool | Running-config modified but not saved. |
| `created_by` | varchar(64) | Who added it. Differs from the owner when a super admin granted it. |
| `access_level` | varchar(16) | `read` or `write`. `read` is enforced at the SSH layer. |
| `terminal_access` | bool | Whether the owner may open the browser terminal to it. |
| `created_at` | datetime | |

### `site_labels` (5)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(64) | Normalised: trimmed, collapsed whitespace, lowercase. |
| `owner_username` | varchar(64) idx | Labels are private to the user. |
| `created_at` | datetime | |
| `hidden` | bool | Marks a **built-in** label the user has hidden. A hidden built-in keeps existing for everyone else. |

### `audit_logs` (11)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `timestamp` | datetime idx | UTC. |
| `level` | varchar(16) | `SUCCESS` · `INFO` · `WARN` · `ERROR`. |
| `username` | varchar(64) idx | Actor. |
| `message` | varchar(255) | One-line summary. |
| `description` | text | Full detail: CLI sent, raw switch output, before/after. |
| `undo_commands` | text | The command set that reverses this entry, or null when it cannot be undone. |
| `undo_label` | varchar(255) | What the Undo button says it will do. |
| `switch_id` | int | Which switch, for the dashboard's per-switch view. |
| `ip_address` | varchar(64) | The caller's address, from `ClientIPMiddleware`. |
| `event_type` | varchar(32) | Machine-readable kind, used by the dashboard tiles. |

### `templates` (11)

A saved set of rule lines that can be re-applied later.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `name` | varchar(64) | |
| `owner_username` | varchar(64) | |
| `switch_type` | varchar(32) | The platform the lines were written for. |
| `acl_kind` | varchar(16) | |
| `direction` | varchar(8) | |
| `lines` | text | The rule lines. |
| `reversed_lines` | text | The same set with source and destination swapped. |
| `skipped_reversal_count` | int | Lines that could not be reversed, so the UI can say how many. |
| `created_at` · `updated_at` | datetime | |

### `template_shares` (3)

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `template_id` | int | |
| `username` | varchar(64) | Who it is shared with. Only admins can hold a share; demoting an admin to `user` deletes their shares, because a template naming somebody who can no longer open the page is a lie on the screen. |

### `app_settings` (5)

One row, holding the instance-wide settings a super admin controls.

| Column | Type | Notes |
|---|---|---|
| `id` | int PK | |
| `idle_timeout_minutes` | int | Automatic sign-out. Null or 0 means no timeout. |
| `log_auto_delete_days` | int | Retention period, or null for never. |
| `log_auto_delete_zip` | bool | Export to ZIP before deleting. |
| `log_retention_last_run` | datetime | Set by the six-hourly sweep. |

### `switch_health` (33)

One snapshot per switch per scan, written by `health_collector`. The dashboard
reads the newest and never goes to SSH itself.

| Group | Columns |
|---|---|
| Identity and outcome | `id`, `switch_id`, `collected_at`, `scanned_by`, `duration_ms`, `status`, `error` |
| Inventory | `acl_count`, `rule_count`, `object_group_count` |
| Findings | `redundant_count`, `trailing_redundant_count`, `wrong_direction_count`, `summarizable_count`, `summary_suggestion_count` |
| Schedules | `time_ranges_total`, `time_ranges_inactive`, `time_ranges_expired`, `rules_with_dead_schedule` |
| VPC | `vpc_peer_id`, `vpc_sync_status`, `vpc_mismatch_count`, `vpc_binding_mismatch_count` |
| TCAM | `tcam_status`, `tcam_source`, `tcam_error`, `tcam_max`, `tcam_in_used`, `tcam_in_free`, `tcam_in_pct`, `tcam_out_used`, `tcam_out_free`, `tcam_out_pct` |

### `access_requests` (21)

A read-only user asking an admin to open a path. Statuses:
`pending` · `granted` · `rejected` · `cancelled`.

| Group | Columns |
|---|---|
| Who and when | `id`, `requester_username`, `created_at` |
| Which switch | `switch_id`, `switch_ip`, `switch_label` — the IP and label are copied, so the request still reads correctly after the switch is renamed or removed |
| The flow | `src_ip`, `dst_ip`, `protocol`, `port`, `icmp_type`, `denied_side`, `vlan`, `acl_name`, `matched_rule` |
| The ask | `remark` |
| Resolution | `status`, `resolved_at`, `resolved_by`, `resolution_note`, `seen_by_requester` |

### Migrations

`init_db()` calls `_run_migrations()`, which reads `PRAGMA table_info` and issues
`ALTER TABLE ... ADD COLUMN` for anything missing. Additive only — existing data
is never dropped. To add a column: declare it on the model **and** add it to the
`wanted` dict in `database.py`.

`RETIRED_THEMES` runs in the same pass, remapping the theme id of any user still
holding a withdrawn theme so their next page load has a palette that exists.

---

## 4. Authentication, Roles & Lockout

### Tokens

| Aspect | Detail |
|---|---|
| Scheme | OAuth2 password flow, JWT bearer. |
| Hashing | bcrypt via the `bcrypt` package directly (passlib was dropped — it breaks on bcrypt ≥ 4.1). |
| Lifetime | 480 minutes (8 hours), `ACCESS_TOKEN_EXPIRE_MINUTES`. |
| Storage | `localStorage`. Validated against `/api/auth/me` on every page load. |
| Expiry handling | Any 401 on a request that carried a token clears local state and returns to the login screen with an explanatory message. |
| Signing key | Derived from `SECRET_KEY` by HKDF, separately from the credential-encryption key — see §14. |
| Revocation | Each user carries `tokens_valid_from`. A token whose `iat` predates it is refused with "Your access changed. Please sign in again.", even though its signature and expiry are still valid. Set by a role change, a password reset, or changing your own password. |
| Idle timeout | A super admin can set an instance-wide idle sign-out in minutes (`app_settings.idle_timeout_minutes`). Unset means the token's own eight hours are the only limit. |

### Trusted hosts

An optional per-user allow list of IPs and prefixes, comma-separated.

| Rule | Detail |
|---|---|
| Effect | Sign-in is refused from an address outside the list. Empty means no restriction. |
| Evaluated against | The address the request actually arrived from. Behind a reverse proxy that is the proxy unless uvicorn is started with `--proxy-headers` and an allow-list — without it the check compares every user against `127.0.0.1`. See `README.md`. |
| Format | IPv4 addresses or CIDR prefixes. Invalid entries are rejected when set, not silently skipped. |
| Who sets it | An admin may set their own (`PUT /api/auth/me/trusted-hosts`); a super admin may set anyone's. |
| Failure | Logged as a failed sign-in naming the rejected address, so a locked-out user is diagnosable. |

### Presence

There is no session store. `users.last_seen` and `users.active_ips` are stamped
on each authenticated request, and "active" means seen inside the idle-logout
window (15 minutes when no timeout is set). Signing out clears the marker
immediately; closing the tab lets it age out. A role change is refused with 409
while the target is still active, because changing authority underneath someone
mid-operation is how half-finished writes happen.

### Password policy

Enforced identically in `auth.validate_password` (authoritative) and
`V.password` in `app.js` (immediate feedback).

| Requirement |
|---|
| Minimum 12 characters |
| At least one uppercase letter |
| At least one lowercase letter |
| At least one digit |
| At least one special character |
| A new password must differ from the current one (self-service change only) |

### Roles

| Role | Read features | Write features | User management | Notes |
|---|---|---|---|---|
| `user` | Yes | No | No | Owns its own switch inventory and locations. |
| `admin` | Yes | Yes | Yes, for `user` and `admin` | Cannot touch a super admin. |
| `super_admin` | Yes | Yes | Yes, for everyone | Can delete or modify other super admins. Sees all users' logs. |

Privilege comparison uses a numeric rank (`user`=1, `admin`=2,
`super_admin`=3). An actor may manage a target when
`rank(actor) >= rank(target)`. This single rule governs role changes, deletion,
password resets and unlocks.

### Lockout policy

| Aspect | Value |
|---|---|
| Threshold | 3 failed attempts |
| Window | 5 minutes (rolling from the first failure) |
| Lock duration | 5 minutes |
| Response while locked | HTTP 423 with the remaining time |
| Counter reset | Successful sign-in · window expiry · administrator unlock |
| Applies to | Existing usernames only |

Behaviour details:

| Rule | Detail |
|---|---|
| Countdown feedback | Failures 1 and 2 report how many attempts remain before the lock. |
| Lock takes precedence | While locked, even the correct password is refused — the password is not evaluated. |
| Unknown usernames | Never locked and never revealed. The response is identical to a wrong password, so the endpoint cannot be used to enumerate accounts. |
| Window expiry | A failure more than 5 minutes after the first one starts a fresh window at count 1. |
| Visibility | `GET /api/auth/users` returns `locked`, `locked_until`, `seconds_remaining` and `failed_attempts`. |
| Unlock authority | Any administrator with equal or higher privilege than the target. A plain user gets 403. |
| Audit trail | Each failure logs `WARN`; reaching the threshold logs `ERROR`; an unlock logs `SUCCESS`. |

UI: the Users table shows a red `🔒 LOCKED 4m` badge, or an amber `2 failed`
badge when failures are recorded but the account is not yet locked. An
**Unlock** button appears for anyone permitted to clear it.

### First-run seeding

On startup, if the `users` table is empty an `admin` account is created with the
password `admin` and the role `super_admin`. If an `admin` account
already exists with a lower role it is promoted to `super_admin`. Change this
password immediately after first sign-in.

---

## 5. User Management

Admin-only page. All actions are confirmed and produce a toast reporting the
outcome.

| Action | Rules |
|---|---|
| Add user | Username must be unique and match `[A-Za-z0-9._-]{2,64}`. Password must satisfy the policy. Only a super admin may create a super admin. |
| Change role | Cannot change your own role. Requires equal or higher privilege than the target. Only a super admin may grant `super_admin`. Setting the role it already holds returns `changed: false` and an informational toast. |
| Delete user | Cannot delete your own account. Requires equal or higher privilege. Cascades — see below. |
| Reset password | Requires equal or higher privilege, or the target being yourself. Enforces the password policy. |
| Unlock | Requires equal or higher privilege. No-op if not locked, reported as such. |
| Change own password | Any signed-in user. Requires the current password. The new password must differ. |

### Deletion cascade

Deleting a user removes everything they own, in this order:

| Step | Detail |
|---|---|
| 1 | Close any live SSH sessions for their switches. |
| 2 | Null `vpc_peer_id` on other users' switches that referenced theirs, preventing dangling pointers. |
| 3 | Delete their switch rows, including the encrypted SSH passwords. |
| 4 | Delete their custom location labels. |
| 5 | Delete the user row. |
| 6 | Log a `WARN` entry with the counts, and report the counts in the response. |

Audit history is deliberately retained after deletion — the record of what an
account did must outlive the account.

---

## 6. Switch Inventory

Every switch belongs to exactly one user. All queries are scoped by
`owner_username`, so one user can never see or reach another user's switches.

| Field | Rules |
|---|---|
| IP address | Validated IPv4. Unique per user; adding the same IP again updates the existing entry. |
| Type | `ios` (access/core) or `nexus`. Changing away from `nexus` clears any VPC pairing on both sides. |
| Location | Must be one of the user's available labels, or unassigned. |
| SSH username | Username for SSH connection to the switch; defaults to the panel user's username if not specified. Can be customized per switch. Displayed in the UI alongside the IP address. |
| SSH password | Always saved, encrypted — see §14. Never returned by the API; only a `has_saved_password` boolean. |
| Enable password | Saved when "Requires enable password" is ticked, encrypted the same way, so a switch needing enable mode keeps working across restarts without re-entry. Never returned by the API. |
| Hostname | Fetched from the switch on add via `show running-config | include ^hostname`, falling back to the prompt, then the IP. |
| Access level | `write` or `read`. See below. |
| Terminal access | Whether the owner may open the browser terminal to this switch. |

### Access level

Each switch row carries an access level, and it is the single most important
guard in the application.

| Rule | Detail |
|---|---|
| Values | `write` (the default) or `read`. |
| Where enforced | `require_write_access()` in `switch_service.py`, at the SSH layer — not in the interface. A `read` switch cannot emit a configuration command even if the API is called directly with a valid admin token. |
| Consequence | A `read` grant is genuinely read-only. Every `show` still works. |
| Who sets it | Whoever granted the switch. A super admin who added a switch for somebody else can change it afterwards through `/api/switches/granted/{id}`. |
| Interface | The write controls are hidden for a `read` switch, but the hiding is a courtesy; the refusal is at the bottom. |

### Credential storage

| Rule | Detail |
|---|---|
| At rest | SSH and enable passwords are encrypted with a key derived from `SECRET_KEY` by HKDF — see §14. The key lives in `.env`, which is gitignored and created at mode 600. |
| Never returned | No endpoint returns either password, in any form. The API exposes booleans only. |
| Never logged | Neither appears in the audit log, in an error message, or in console output. |
| Key rotation | On startup, anything still encrypted under the legacy scheme is re-encrypted with the derived key. A guard refuses to generate a *new* key while unreadable credentials are stored, because rotating again would make them unrecoverable rather than merely unreadable. |
| Backup | The database and `.env` must be backed up together. A database restored beside a different key starts, and users sign in, but every stored switch password is undecryptable and must be re-entered. |
| No hardcoded fallback | No default enable password exists in the codebase. |

### Operations

| Operation | Behaviour |
|---|---|
| Add | Probes the switch before saving. A failed probe returns 502 with a specific reason and saves nothing. The enable password is validated during the probe. |
| Update | Changes location, SSH username, enable flag and/or passwords without re-probing. Replacing a password invalidates the cached session. Reports "Nothing to change" when nothing differs. |
| Bulk add | Several switches at once. A super admin may pass `usernames` to add them for other people, choosing the access level per grant. |
| Reorder | The user's own card order is stored in `users.switch_layout` and used everywhere switches are listed, including the dashboard. |
| Remove | Clears VPC references, closes the session, deletes the row. Nothing on the switch itself is altered. |
| Granted switches | A super admin can list what they granted to others, change the password or access level, or take it back. |

The Manage Switches modal groups cards by location, has a filter box matching
name/IP/location, and badges each card with type, location, SSH username (if different from owner), `ENABLE`,
`UNSAVED`, password state and VPC peer.

---

## 7. Locations (Site Labels)

Ten built-in labels are shared by all users: `site1`, `site2`, `site3`, `site5`,
`site6`, `part`, `part2`, `part3`, `part5`, `part6`.

| Rule | Detail |
|---|---|
| Scope | Custom labels are private to the user who created them. |
| Where managed | Inline in the location dropdown itself — no separate section. |
| Add | The dropdown footer has **＋ Add a location**, which reveals an inline field. Enter saves. The new label is selected automatically. |
| Delete | Custom labels show a ✕ on hover inside the dropdown. Built-ins show a `built-in` tag and cannot be deleted. |
| Delete side effect | Switches using the label become unassigned; the count is reported. |
| Naming | Letters, digits, spaces, dot, dash, underscore. Max 32 characters. Must start with a letter or digit. |
| Normalisation | Trimmed, whitespace collapsed, lowercased — so "Data Center A" and "data center a" are the same label. |
| Limit | 40 custom labels per user. |
| Hiding a built-in | A built-in cannot be deleted, but it can be hidden from your own dropdown. The `hidden` flag on `site_labels` records that per user; the label keeps existing for everyone else. |
| Server authority | A switch may only be assigned a label present in that user's list; anything else is rejected. |

---

## 8. VPC Pairing & Multi-Switch Selection

### Pairing

| Rule | Detail |
|---|---|
| Eligibility | Nexus switches only. |
| Symmetry | Bidirectional — setting A→B also sets B→A. |
| Exclusivity | One peer per switch. Pairing A→B when either already had a peer clears the old links first. |
| Where managed | The **VPC Peer** button on each Nexus card in Manage Switches. |
| Unpair | Select "None" in the same dialog. |
| Automatic clearing | Deleting a switch, or changing its type away from Nexus, clears the pairing on both sides. |

### Selection rules

| Rule | Enforcement |
|---|---|
| Maximum two switches | Client and server. |
| Multi-select is Nexus-only | Client disables ineligible entries; server rejects any mixed set with a message naming the offending switch. |
| Selecting IOS clears others | Choosing an IOS switch replaces the whole selection and explains why via a toast. |
| Peer highlighting | With one Nexus selected, its registered peer is highlighted cyan and labelled `VPC PEER`. |
| Manual pairing allowed | Any two Nexus switches can be selected together. If the second is not the registered peer, a warning toast appears but the operation is permitted. |
| Ordering | The first selection is `PRIMARY`, the second is `PEER`. Object-group lookups use the primary. |

The picker groups switches by location, has a search box, and shows a
context-sensitive hint line explaining the current constraint.

### Multi-switch behaviour by feature

| Feature | Behaviour with two switches |
|---|---|
| Access Checker | Runs independently on each and returns a separate verdict per switch. |
| IP ACL Lookup | Reports the interface and ACLs found on each. |
| ACL Viewer | Lists each switch's ACLs under its own header. |
| Object Groups | Lists each switch's groups separately. |
| Time Ranges | Lists each switch's ranges with independent active state. |
| Redundancy / Summary | Analyses each switch separately. |
| Add ACL Rule | Generates a preview per switch; each is approved and applied individually. |
| Time-range apply | Applied to every selected switch in turn, reporting per switch. |
| Save Config | Runs on every selected switch, reporting per switch. |

Results are always grouped under a per-switch header showing hostname, IP and
type, so a finding is never ambiguous across a VPC pair.

---

## 9. SSH Layer

Netmiko replaced raw paramiko because it handles legacy Cisco algorithm
negotiation, enable mode, paging and prompt detection natively — the earlier
paramiko implementation failed to authenticate against older IOS.

| Aspect | Detail |
|---|---|
| Device types | `ios` → `cisco_ios`, `nexus` → `cisco_nxos`. `iosxe` and `iosxr` are mapped but not surfaced in the UI. |
| Session cache | Keyed by `(username, switch_ip)`. Reused while alive, transparently rebuilt when dead. |
| Concurrency | A per-session lock serialises commands so two requests cannot interleave on one connection. |
| Timeouts | connect 20s, auth 20s, banner 20s; per-command read timeouts of 20–90s by operation. |
| Config mode | `send_config_set` handles `configure terminal` and `end`. Config commands are never sent as raw show commands. |
| Invalidation | Changing a saved password, or removing a switch, closes the session. |

### Error classification

`detect_switch_error()` inspects raw output for Cisco error markers — `% Invalid
input`, `% Incomplete command`, `% Ambiguous command`, `% Access denied`,
`% Authorization failed`, `ERROR:`, `Command rejected`, and a bare `^` marker
alongside `%`. It returns a plain-language sentence.

Connection failures are translated rather than surfaced raw:

| Failure | Message |
|---|---|
| Authentication | Names the username and states that it or the SSH password is wrong. |
| Timeout | Suggests checking the IP, routing and that SSH is enabled. |
| Negotiation | Notes the switch may only support older ciphers or key exchange. |
| Enable rejected | States the enable password was refused. |

Switch faults return HTTP 502 tagged `kind: "switch"`, so the UI can title the
toast "Switch error" rather than blaming the application.

---

## 10. ACL Parsing & Directional Logic

This is the core of the product. All of it is deterministic.

### Rule parsing

`parse_acl_rule()` produces a structured dict from one ACL line, handling:

| Element | Forms |
|---|---|
| Sequence number | Optional leading integer. |
| Action | `permit` · `deny`. |
| Protocol | `ip` · `tcp` · `udp` · `icmp`. |
| NX-OS address | `any` · `host X` · `X.X.X.X W.W.W.W` (wildcard) · `X.X.X.X/LEN` · `addrgroup NAME`. |
| IOS address | `any` · `host X` · `X.X.X.X W.W.W.W` (wildcard) · `object-group NAME`, where the named group has a `Network object group` header. CIDR is not accepted in IOS ACL output. |
| NX-OS port operator | `eq` · `neq` · `lt` · `gt` · `range` · `portgroup NAME`, after either address. |
| IOS service group | `object-group NAME` before both addresses, where the named group has a `Service object group` header. |
| Named ports | ~30 service names (`ssh`, `www`, `https`, `domain`, `rdp`, `sqlnet`, …). |
| Time range | `time-range NAME`. |

### Route interpretation

`parse_route_output()` reads `show ip route <ip>`:

| Output | Interpretation |
|---|---|
| `directly connected, via VlanX` | Gateway is on this switch; VLAN recorded. |
| `directly connected, via <physical>` | Gateway is not on this switch. |
| `via <next-hop>, <interface>` | Gateway is not on this switch. |
| Nothing matched | Not on this switch. |

If neither address resolves to a local VLAN, the switch is reported as not
relevant to that traffic rather than producing a misleading verdict.

### Directional logic

The direction the ACL is applied determines which position in the rule belongs
to the VLAN interface. This is the reference point — **not** the user's
"source" and "destination" labels.

| Applied | Which rule position belongs to the VLAN |
|---|---|
| `in` on VLAN X | The **first** IP in the rule. |
| `out` on VLAN X | The **second** IP in the rule. |

### Bidirectional versus one-way

**Case 1 — no port anywhere in the rule** (`ip`, `icmp`, or `tcp`/`udp` with no
port). The rule is bidirectional on that ACL and interface. If the two rule
addresses match the queried pair in *either* order, it matches.

```
ACL in on Vlan10:  permit tcp host 192.168.10.1 host 192.168.20.1
  192.168.10.1 → 192.168.20.1   MATCH
  192.168.20.1 → 192.168.10.1   MATCH   (bidirectional)
```

**Case 2 — a port operator is present** (`eq`, `neq`, `lt`, `gt`, `range`, an
NX-OS portgroup, or an IOS service object group). The rule is one-way. For an
operator following an address, that address is the destination of the port
access. An IOS service object group precedes both addresses and applies to the
second (destination) address.

```
permit tcp host 192.168.10.1 host 192.168.20.1 eq 22
  → port 22 belongs to 192.168.20.1
  192.168.10.1 → 192.168.20.1:22   MATCH
  192.168.20.1 → 192.168.10.1:22   NO MATCH
  192.168.20.1 → 192.168.10.1      NO MATCH

permit tcp host 192.168.10.1 eq 22 host 192.168.20.1
  → port 22 belongs to 192.168.10.1
  192.168.20.1 → 192.168.10.1:22   MATCH
  192.168.10.1 → 192.168.20.1:22   NO MATCH
```

Verified by platform-specific parsing and evaluation tests covering both
operator positions, wrong ports and protocols, IOS service/network group
placement, NX-OS prefixes, multiple `eq` ports, ICMP, subnet matching and deny
rules.

### Evaluation order

| Step | Behaviour |
|---|---|
| 1 | Rules are processed strictly top to bottom. |
| 2 | Evaluation stops at the first match; its action is the verdict. |
| 3 | A rule whose time range is inactive is skipped as though absent. |
| 4 | No match means the implicit deny at the end of the ACL applies. |
| 5 | No ACL on the interface means permitted by default, stated explicitly. |

### Address matching

Both `/32` hosts and subnets are supported. Wildcard masks are converted to
prefix lengths and compared with `ipaddress`; the queried value must be fully
contained within the rule's network. `any` matches everything.

### Object groups

Object groups are fetched and classified before ACL rules are parsed. NX-OS
`addrgroup` references must resolve to an `IPv4 address object-group`, and
`portgroup` references must resolve to a `Protocol port object-group`. On IOS,
the parser uses the `show object-group` inventory to decide whether each
`object-group` token is a network address or a service group. IOS service-group
member protocols (`tcp`, `udp`, or `tcp-udp`) must match the requested protocol
in addition to the member's port condition. Groups are loaded once per ACL and
cached for that evaluation.

### Redundancy detection

A rule is redundant when an **earlier** rule fully covers it: same action,
compatible protocol (or the earlier one is `ip`), source and destination
networks are subnets of the earlier rule's, and the port condition is covered
(`eq` within `eq`, `eq` within `range`, `range` within `range`, or the earlier
rule has no port restriction). Reports both lines and the positions.

### Summary suggestions

Permit rules are grouped by protocol, destination and port condition. Source
networks in each group are collapsed with `ipaddress.collapse_addresses`. A
suggestion is produced only when the collapsed set is strictly smaller than the
original, so a summary can never widen what the ACL already permits. Rules
referencing object groups are skipped. Suggestions are advisory and require
explicit approval to apply.

---

## 11. Read Features

None of them modify a switch. Available to every role except the Dashboard,
which is admin and above — a regular admin sees their own logs and their own
switches there, a super admin sees everyone's.

| Feature | Inputs | Output |
|---|---|---|
| **Access Checker** | Source, destination (IP/subnet/`any`), protocol, optional port | Per switch, a Source Side and Destination Side verdict of PERMITTED / DENIED / N/A, the interface, the ACL and direction, the reason, and the matched rule. |
| **IP ACL Lookup** | One IP | Per switch: whether the gateway is local, which interface, and every ACL applied to it with its rules expandable. States plainly when no ACL is applied. |
| **ACL Viewer** | ACL name, or blank for all | Per switch, collapsible ACL panels with rule counts, the interfaces and directions each is applied to, colour-coded rules, and an unused marker. Admins get a per-rule remove button. |
| **Object Groups** | — | Per switch, address and port groups in separate sections with member counts and expandable members. |
| **Time Ranges** | — | Per switch, every configured range with an ACTIVE NOW / NOT ACTIVE / STATUS UNKNOWN badge and its entries. |
| **Redundancy Checker** | ACL name, or blank for all | Two categories, counted separately. **Redundant**: each rule paired with the earlier rule that covers it. **Dead schedule** (orange): rules whose time range has expired and can never match again, with the entries that prove it. Reports explicitly when none are found. |
| **VPC Sync Check** | Two paired peers | ACLs that differ between the peers — present on one only, or present on both with different contents — plus interface-binding mismatches. |
| **ACL Report** | ACL name | A printable per-ACL report: the rules, where the ACL is applied, and the findings against it. |
| **Summary Suggester** | ACL name, or blank for all | Per switch and ACL, each suggested summary with the exact rules it would replace, and an apply button for admins. |
| **Dashboard** (admin and above) | Time window, or one bar of it | Eight tiles across every user — changes, rules added and removed, failed operations, failed sign-ins, active users, switch count, unsaved configs — each one clickable to see the entries behind it. A bar strip labelled per day or hour; clicking a bar narrows every tile and list to that period. Two scrolling feeds: **Last actions** (writes only) and **User activity** (everything logged). Plus **Switch analyze**, a per-switch table from the last scan: redundant, wrong-rule and summarizable counts, dead schedules, VPC sync and TCAM use, each count linking into the page that shows the detail, and a per-switch Scan button. Rows follow the same location and switch order as Switch Management. Dead-schedule counts appear alongside the redundancy ones and are never folded into them. A pending access-request count appears for admins who can act on them. |

Object-group discovery uses `show object-group` and classifies groups only from
platform-specific headers. NX-OS uses `IPv4 address object-group NAME` and
`Protocol port object-group NAME`; IOS uses `Network object group NAME` and
`Service object group NAME`. Member syntax is never used to infer the group
type, and headers belonging to the other platform are ignored.

---

## 12. Write Features

Admin-only. Every write follows the same discipline.

### Universal rules

| Rule | Detail |
|---|---|
| Preview | The exact CLI is displayed before anything is sent. |
| Confirmation | An explicit dialog, showing those commands, must be approved. |
| Editable | Generated rule syntax can be edited before applying; the edited text is re-validated. |
| Per-switch approval | With a VPC pair, each switch is approved separately. |
| Undo | Every successful write returns an undo command set. The Undo button shows those commands in its own confirmation before running. |
| Running-config only | No write saves the configuration. |
| Error surfacing | The full raw switch output is shown, the operation halts, and nothing is saved. |
| Audit | Success and failure are both logged with the commands and raw output. |
| Pending flag | Any successful write marks the switch as having unsaved changes. |

### Add ACL Rule

| Aspect | Detail |
|---|---|
| Inputs | Source and destination as IP, subnet, `any` or generic `addrgroup NAME`; protocol; optional port, range or generic `portgroup NAME`; optional sequence number. Generic group keywords are converted to the selected switch's CLI syntax. |
| Group pickers | ⊕ buttons load live, header-classified object groups from the primary switch. Preview rejects missing groups and groups used as the wrong type. |
| Sequence | Auto mode tries free multiples of ten in ascending order (`10`, `20`, `30`...). Every choice must precede the earliest effective explicit deny. If no multiple of ten is available below that deny, it tries `1`, `2`, `3`...; if no lower sequence exists, preview fails. Without object groups, effective rules come from Access Checker. With object groups, the complete generated rule is compared structurally against the ordered ACL. If no explicit deny is found, the first free multiple of ten is used. |
| Target discovery | `show ip route` locates relevant VLANs. Object-group mode uses one route probe per address-group member declaration; subnet and range members are not expanded into every address. |
| Syntax generation | Built from the directional logic in §10 and the managed switch type. NX-OS emits `addrgroup`/`portgroup` and enters `ip access-list NAME`; IOS emits network `object-group` operands, places service `object-group` before both addresses, and enters `ip access-list extended NAME`. |
| Existing-access pre-check | Requests without groups use the complete shared Access Checker workflow. Object-group requests parse the proposed full rule and ordered ACL rules, checking protocol breadth (`ip` covers ICMP/TCP/UDP), address/subnet containment and port coverage. When the remaining rule fields are compatible, group members are resolved selectively: service/port groups can cover requested member ports, and address groups can cover requested member hosts/networks. Identical generated rules targeting the same ACL are merged. |
| No ACL on interface | Reported as nothing to add, since traffic is already permitted there. |
| Permit only | Deny is rejected in the browser and at the API. |
| Undo | `no <sequence>` in the same ACL. |
| Apply verification | Switch error text is checked, then the ACL is read back. Success is reported only when the exact normalized rule is present; otherwise configuration and verification output are returned as a failure. |

### Remove a rule

Available per rule in the ACL Viewer. Captures the original line before
deleting so the undo restores it verbatim rather than approximating it.

### Apply a summary

Removes the listed sequences and adds the summary in one config block. The ACL
is re-read first; if it changed since the suggestion was generated the
operation is refused and re-analysis is requested. The undo removes the summary
and restores every original line.

### Time ranges

| Aspect | Detail |
|---|---|
| Entry types | Periodic (day selection plus start/end time) and absolute (start and/or end date and time). |
| Pickers | Native time and date controls. |
| Validation | `HH:MM` 24-hour; start earlier than end for both periodic and absolute; at least one entry; at least one bound on an absolute entry. |
| Date conversion | The browser's `YYYY-MM-DD` is converted to Cisco's `1 Jan 2026`. |
| Multi-switch | Applied to each selected switch in turn with per-switch reporting. |
| Undo | A newly created range is deleted; an amended one has its added entries reversed. |

### ACL lifecycle

| Aspect | Detail |
|---|---|
| Create | `POST /api/analysis/acl-create-preview` then `/api/write/acl-create`. Builds `ip access-list [extended] NAME` for the target platform, with optional initial rules. |
| Delete | `/api/write/acl-delete`. The ACL's current contents are captured first, so the undo restores every line rather than an empty shell. |
| Attach / detach | `/api/write/acl-interface` applies or removes an ACL on an interface in a direction. |
| Direction flip | `/api/write/acl-interface-flip` moves an ACL that is applied the wrong way round, previewed by `/api/analysis/reverse-direction-preview`. |

### Object groups

| Aspect | Detail |
|---|---|
| Create / replace | `/api/write/object-group-preview` then `object-group-apply`. |
| Members | Add, edit and delete individually — `object-group-member-add`, `-member-edit`, `-member-delete` — so one wrong member does not mean rewriting the group. |
| Delete | `object-group-delete`. Refused with the referencing rules named when the group is still in use, because deleting a group an ACL references changes what that ACL does. |
| Type discipline | Address and port groups are told apart by platform-specific headers only, never by member syntax. See §11. |

### VPC sync

| Aspect | Detail |
|---|---|
| Preview | `/api/write/acl-sync-preview` shows the exact difference between the two peers. |
| Apply | `/api/write/acl-sync` touches only the sequence numbers that actually differ, rather than removing and rewriting the ACL. |
| Direction | Explicitly source → target; which peer is authoritative is the operator's choice, never inferred. |

### Templates

| Aspect | Detail |
|---|---|
| What | A saved set of rule lines, with the reversed form generated alongside so a template written one way can be applied the other. |
| Reversal | Lines that cannot be reversed are counted, not silently dropped, and the count is shown. |
| Sharing | Shareable with other admins only. Demoting an admin to `user` deletes their shares, and the audit entry says how many. |
| Apply | `/api/analysis/template-apply-preview` then `/api/write/template-apply`, following the same preview → confirm → verify → undo path as any other write. |

### Bulk operations

| Aspect | Detail |
|---|---|
| Apply all summaries | Applies every suggestion currently on screen after one review, per switch and per ACL, reporting each. |
| Remove all redundancies | The same for redundant rules. Both work from the result already loaded, so nothing is analysed twice and nothing is applied that was not shown. |
| Bulk save config | `/api/write/bulk-save-config` saves several switches in one operation, reporting per switch. |
| Rule edit | `/api/write/rule-edit` replaces one rule's text in place, capturing the original line so the undo restores it verbatim. |

### Access requests

Not a switch write, but the same discipline. A read-only user submits a request
describing the flow they need; an admin who can act on it sees it in a queue and
can open it straight into a pre-filled Add ACL Rule form.

| Aspect | Detail |
|---|---|
| Who can raise one | Any signed-in user, from a denied Access Checker verdict. The request carries the flow, the switch, the denied side, the VLAN, the ACL and the matched rule. |
| Editing | The requester can amend their own remark or cancel, while it is still pending. |
| Queue scoping | A request is not shown to an admin who holds that switch read-only, or does not hold it at all — they could not act on it either way, and the only thing an unactionable row offers is a dead end. Super admins see everything. Your own requests never appear in your own queue. |
| Resolution | **Mark as done** or **dismiss**, each with an optional note. The audit entry says the admin marked it done — not that they granted it, because the two are not the same and the log should not claim more than it knows. |
| Notification | The requester is told when a request is answered; `seen_by_requester` stops the same answer being announced twice. |

### Save Config

| Aspect | Detail |
|---|---|
| Trigger | Only the Save Config button in the top bar. Nothing else runs it. |
| Scope | Every currently selected switch. |
| Confirmation | Names the switches, lists the command, and states which have pending changes. |
| Indicators | The button turns amber with a pulsing ring and a count badge; an amber banner appears under the top bar with a Save Now button; switch cards show an `UNSAVED` badge. |
| State source | The `pending_changes` column, so the indicator survives a reload and is per switch. |
| Clearing | Only a successful save clears the flag. |
| Failure | Per-switch results with raw output; the flag stays set. |
| Prompt handling | A destination-filename prompt is answered automatically. |

---

## 13. Audit Logging

Every meaningful action is recorded. Writes are best-effort — a logging failure
rolls back and is swallowed so it can never break the operation.

### Fields

The table shows **Date/Time · Level · User · Message · Log Description**. The
description holds the CLI sent, raw switch output, and before/after values,
shown in a modal.

Each row also carries fields the table does not show:

| Field | Used for |
|---|---|
| `undo_commands` / `undo_label` | The Undo button, which shows those commands in its own confirmation before running them. Null when the entry cannot be undone. |
| `switch_id` | The dashboard's per-switch views. |
| `ip_address` | Where the action came from. Recorded from the connection, not from a header a client could set — behind a proxy this needs `--proxy-headers`, or every entry says `127.0.0.1`. |
| `event_type` | A machine-readable kind, which is what the dashboard tiles count. |

### Visibility

| Role | Sees |
|---|---|
| `user` | Their own entries only. |
| `admin` | Their own entries only. |
| `super_admin` | Every user's entries, including other super admins'. |

Enforced server-side by filtering the query, not by hiding UI.

### What is logged

| Area | Events |
|---|---|
| Authentication | Sign-in and sign-out; each failed attempt with the attempt count; blocked attempt while locked; lock triggered. |
| Users | Create, role change, delete (with cascade counts), password reset, own password change, rejected password change, unlock. |
| Switches | Add, update (listing what changed), remove, failed add with the SSH reason, grants to other people and changes to them. |
| Locations | Add, delete with the number of switches un-assigned. |
| VPC | Pair, unpair. |
| Reads | Access checks, IP lookups, redundancy and summary runs, with the parameters and switches involved. |
| Writes | Rule add, rule delete (recording the removed line), summary apply, time-range apply, undo, save config — each with commands and outcome. |

### Retention

| Aspect | Detail |
|---|---|
| Manual | A super admin can delete entries older than a chosen age, optionally exporting them to a ZIP under `backend/log_backups/` first. |
| Scheduled | `app_settings.log_auto_delete_days` enables an automatic sweep. |
| Cadence | A background task checks every six hours for the life of the process. Deleting is idempotent, so a missed or doubled check never double-deletes and no locking is needed. |
| Not a scheduler | This is the only recurring task in the backend. Nothing else runs on a timer. |

UI: filter by level, search across user and message, refresh on demand, and a
detail modal per entry. Capped at 500 rows in the UI and 2000 at the API.

---

## 14. Validation & Security

### Two-layer validation

The browser validates for immediate feedback; the server validates
authoritatively. The rules are deliberately mirrored so behaviour is
consistent, but the client is never trusted.

| Input | Rules |
|---|---|
| IPv4 | Four octets, each 0–255. |
| Subnet | Valid network with prefix 0–32. |
| Address field | IP, subnet, `any`, or `addrgroup NAME`. Source and destination cannot both be `any`. |
| Port | 1–65535. In a range, the first must be lower than the second. Only valid for TCP/UDP — a port with ICMP or `all` is rejected with an explanation. |
| Port group | `portgroup NAME` with a valid identifier. |
| Sequence | Integer 1–4294967294. |
| Identifier | ACL, object-group and time-range names: starts alphanumeric, then letters, digits, dot, dash, underscore, max 64. |
| Username | 2–64 characters of letters, digits, dot, dash, underscore. |
| Password | Per §4. |
| Time | `HH:MM`, 24-hour. |
| Date | Cisco `D Mon YYYY`. |
| Location | Must exist in the user's own label list. |
| Switch type | `ios` or `nexus`. |
| Rule line | Must begin with `permit` (optionally after a sequence number). Deny is refused. Max 400 characters. |

### CLI injection defence

Every value that could reach a switch passes `check_cli_safe()`, which rejects
`;` `|` `&` `` ` `` `$` `<` `>` and newlines. This blocks command chaining —
an ACL name of `FOO; shutdown` is refused, not executed. Applied to ACL names,
group names, time-range names, rule lines, undo command sets and location
names.

### Other measures

| Measure | Detail |
|---|---|
| Password storage | bcrypt, per-password salt. |
| Secret key | Generated on first run with `secrets.token_urlsafe(48)` and written to a gitignored `.env`. Nothing usable ships in the repository — anything that did would be public by definition. |
| Key separation | Signing and credential-encryption keys are derived from the secret separately, by HKDF-SHA256 with distinct `info` labels, rather than by truncating and zero-padding it. The whole secret contributes, and a leaked signing key reveals nothing about the stored credentials. |
| Credential storage | SSH and enable passwords are Fernet-encrypted under the derived credential key. Never returned by any endpoint, never logged. |
| Legacy migration | Credentials written under the old scheme are re-encrypted at startup. A guard refuses to generate a new key while unreadable credentials are stored, since rotating again would make them unrecoverable rather than merely unreadable. |
| Read-only switches | Enforced at the SSH layer by `require_write_access()`, so a `read` grant cannot emit a configuration command however the API is called. |
| Trusted hosts | Optional per-user IP/prefix allow list, checked at sign-in against the connecting address. |
| Token revocation | A role change, password reset or password change stamps `tokens_valid_from`, refusing every token issued earlier. |
| Terminal origin check | The terminal websocket verifies the `Origin` header before accepting the connection. |
| Database file | `chmod 600` on startup. |
| CORS | Same-origin by default; `GIGACL_CORS_ORIGINS` is the only way to widen it. |
| Ownership scoping | Every switch query filters on `owner_username`. |
| Deny rules | Blocked in the browser and at the API. |
| Brute force | Lockout per §4. |
| Account enumeration | Unknown and wrong-password responses are identical. |
| Self-lockout | Cannot delete your own account or change your own role. |
| Privilege escalation | Granting `super_admin` requires being one. |
| Path traversal | The SPA fallback resolves the path and confirms it stays inside the frontend directory. |
| API 404s | `/api/*` never falls through to the SPA handler. |
| Security headers | `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`. |
| Static caching | `no-store` on `/static/*` so a stale bundle cannot persist. |
| XSS | All interpolated values pass through `esc()`; values embedded in inline handlers use `jsq()`. |
| Error separation | Switch faults are tagged `kind: "switch"` and reported as switch errors, distinct from application errors. |
| Secrets in logs | Passwords are never written to the audit log. |

### Error message quality

Pydantic's raw validation output is rewritten into plain sentences by a
dedicated handler, with field names mapped to human labels. `switch_ids: []`
becomes "Select at least one switch." rather than a nested type error.

---

## 15. Frontend & UX

Vanilla JavaScript and CSS — no framework, no build step. `index.html`,
`app.js`, `style.css`.

### Themes

Six, chosen from the sidebar, stored per user on the server (`users.theme`) and
mirrored in `localStorage` so the first paint after a reload is already correct.
Each is a block of CSS custom properties on `html[data-theme="..."]`, so
switching repaints instantly without reloading. Every component reads the
tokens; no colour is hard-coded.

| Id | Name | Character |
|---|---|---|
| `dark` | Midnight | The default. Deep blue-black. |
| `slate` | Slate | Cooler and flatter than Midnight. |
| `carbon` | Carbon | Near-monochrome, highest contrast of the dark set. |
| `light` | Daylight | The plain light theme. |
| `glacier` | Glacier | Light, cold, blue-tinted. |
| `evermore` | Evermore | Warm light; formerly `sepia`. |

Withdrawn themes are listed in `RETIRED_THEMES` in `database.py`, which remaps
any user still holding one at startup — `sepia` and `evermorr` to
`evermore`; `liquid`, `nocturne` and `ember` to `glacier`; `contrast` to
`carbon`; `nord` to `slate`. Removing a theme
without adding it there leaves those users on a palette that no longer exists.

### Custom select

Native `<select>` option lists cannot be styled and render with the OS grey
palette. The fix wraps each select: the real element stays in the DOM
(so `.value`, `change` events and existing code keep working) but is visually
replaced by a themed button and menu.

| Capability | Detail |
|---|---|
| Keyboard | Arrows move, Enter selects, Escape closes, Tab exits. |
| Placement | Flips upward when there is not enough room below. |
| Selected row | Highlighted. Deliberately no checkmark — reserving room for one indented every label, including the ones without it. |
| Option metadata | Rows can carry a tag (`built-in`, `yours`). |
| Per-option delete | Rows can carry a ✕ that runs a handler. |
| Inline add | An optional footer action reveals a field for creating a new value without leaving the dropdown. |

Registered per select via `SELECT_EXTRAS` — used for locations, and available
for any future dropdown needing the same treatment.

### Notifications

Toasts in the top-right, colour-coded by kind, with a title, optional detail, a
timing bar and manual dismissal. Every action reports its outcome, including
"no change made" when a role or pairing already had the requested value.

### Feedback and motion

| Element | Behaviour |
|---|---|
| Skeletons | Shimmer placeholders while switch data loads. |
| Button busy state | Spinner plus label, restored afterwards. |
| Page entry | Content fades and lifts in; result cards stagger. |
| Modals | Scale-and-fade in; the close button rotates on hover. |
| Nav | Items slide right and their icon scales on hover; the active item has a gradient bar. |
| Login | Three drifting blurred orbs behind a glass card. |
| Pending save | The Save button pulses amber. |
| Live status | A pulsing green dot on each per-switch header. |

### Layout

Fixed sidebar with brand, switch picker, grouped navigation and a user footer.
A sticky top bar holds the page title, the active-switch chip and the Save
Config button. Collapses to a stacked layout under 860px.

### Pages

Seventeen, grouped in the sidebar. Hidden entries appear only for the role that
can use them.

| Group | Pages |
|---|---|
| Analysis | Dashboard *(admin+)* · Access Checker · IP ACL Lookup · ACL Viewer · Redundancy · Summary Suggester · VPC Sync Check |
| Operations | Add ACL Rule *(admin)* · Add ACL *(admin)* · Object Groups · Time Ranges · Templates *(admin)* · Reverse Direction *(admin)* |
| Account | Activity Logs · Users · My Requests · Change Password |

The switch terminal is a floating window rather than a page, opened from the
header and dockable, minimisable and maximisable over whatever page is showing.

### Modals

Fourteen: Manage Switches · VPC Peer · Edit Switch · ACL/Group Picker · Reset
Password · Rename User · Trusted Hosts · Generic Confirm (with CLI display) ·
Log Detail · ACL Report · Object-Group Edit · Rule Edit · Keyboard Shortcuts ·
About.

All close on the ✕, on a backdrop click, or with Escape. Escape resolves
innermost-first: dropdown, then modal, then switch picker.

---

## 16. API Reference

Every route registered in `main.py`, grouped by area. All of them require a
bearer token except `POST /api/auth/token` and `GET /api/health`.

Role column: **any** = any signed-in user · **admin** = `admin` or
`super_admin` · **super** = `super_admin` only.

### Health

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/health` | — | Liveness for a service manager, proxy or monitor. Unauthenticated and deliberately empty of detail: `{"status":"ok"}`, or 503 when the database cannot be reached. |

### Meta and locations

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/meta` | any | Sites (built-in and the user's own), switch types, roles. |
| POST | `/api/sites` | any | Add a custom location. |
| DELETE | `/api/sites/{name}` | any | Delete a custom location, or hide a built-in. |

### Authentication and account

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/auth/token` | — | Sign in. 401 on bad credentials, 423 when locked, 403 from an untrusted host. |
| GET | `/api/auth/me` | any | Current username, role, theme and preferences. |
| GET | `/api/auth/session` | any | Session state without refreshing the presence marker — used by the idle-timeout check so polling does not itself keep you "active". |
| POST | `/api/auth/logout` | any | Clear the presence marker. Does not revoke the token. |
| PUT | `/api/auth/me/password` | any | Change own password. Requires the current one; revokes every other session. |
| PUT | `/api/auth/me/theme` | any | Set your theme. |
| PUT | `/api/auth/me/mega` | any | Set your rule-count unit label. |
| PUT | `/api/auth/me/mega-visible` | any | Show or hide that label. |
| PUT | `/api/auth/me/trusted-hosts` | admin | Set your own trusted-host list. |

### User management

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/auth/users` | admin | All users with lock state and presence. |
| POST | `/api/auth/users` | admin | Create a user. Only a super admin may create a super admin. |
| PUT | `/api/auth/users/{id}/role` | admin | Change a role. 409 while the target is still active. Revokes their tokens; drops their template shares on demotion to `user`. |
| PUT | `/api/auth/users/{id}/username` | super | Rename an account. |
| PUT | `/api/auth/users/{id}/password` | admin | Reset a password. Revokes their tokens. |
| PUT | `/api/auth/users/{id}/trusted-hosts` | super | Set anyone's trusted-host list. |
| POST | `/api/auth/users/{id}/unlock` | admin | Clear a lockout. |
| DELETE | `/api/auth/users/{id}` | admin | Delete a user and cascade. |

### Logs and settings

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/logs` | any | Audit log, scoped by role. |
| POST | `/api/logs/undo` | admin | Revert a logged change. Only the admin who made it. |
| POST | `/api/logs/delete-older-than` | super | Delete old entries, optionally exporting to ZIP first. |
| PUT | `/api/settings/log-retention` | super | Configure the scheduled sweep. |
| PUT | `/api/settings/idle-timeout` | super | Set or clear the instance-wide idle sign-out. |

### Dashboard

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/dashboard/activity?window=&start=&end=` | admin | Counts and feeds for `1h`/`24h`/`7d`/`30d`. `start`/`end` narrow the tiles to one bar without shrinking the strip. An admin sees their own logs and switches; a super admin sees everyone's. Database only, no SSH. |
| GET | `/api/dashboard/activity/detail?kind=` | admin | The entries behind one tile. |
| GET | `/api/dashboard/health` | admin | Per-switch counts from the last scan. No SSH. |
| POST | `/api/dashboard/health/scan` | admin | Sweep own switches over SSH and store snapshots. 409 while one is running. |

### Switches

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/switches` | any | The user's switches. |
| POST | `/api/switches` | any | Add or update one switch; probes over SSH before saving. |
| PUT | `/api/switches` | any | Update password/location/enable/SSH username without probing. |
| DELETE | `/api/switches/{id}` | any | Remove. |
| POST | `/api/switches/bulk` | any | Add several. `usernames` (super admin only) adds them for other people. |
| PUT | `/api/switches/order` | any | Store the user's own card ordering. |
| POST | `/api/switches/vpc-pair` | any | Set or clear a VPC peer. |
| GET | `/api/switches/granted` | super | Switches you added for other people. |
| PUT | `/api/switches/granted/{id}` | super | Change the password or access level of one you granted. |
| DELETE | `/api/switches/granted/{id}` | super | Take back one you granted. |

### Analysis — read only

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/acl/check` | any | Access check per switch, both sides. |
| POST | `/api/acl/check-ip` | any | Interface and ACLs for one IP on the selected switches. |
| POST | `/api/acl/check-ip-global` | any | The same across every switch the user holds, to find which one owns the gateway. |
| POST | `/api/analysis/list-acls` | any | ACL names. |
| POST | `/api/analysis/view-acl` | any | One ACL with rules and interfaces. |
| POST | `/api/analysis/view-all-acls` | any | All ACLs. |
| POST | `/api/analysis/acl-report` | any | The printable per-ACL report. |
| POST | `/api/analysis/redundant` | any | Redundant and dead-schedule rules for one ACL. |
| POST | `/api/analysis/redundant-all` | any | The same for all ACLs. |
| POST | `/api/analysis/suggest-summary` | any | Summaries for one ACL. |
| POST | `/api/analysis/suggest-summary-all` | any | Summaries for all ACLs. |
| POST | `/api/analysis/object-groups` | any | Address and port groups. |
| POST | `/api/analysis/time-ranges` | any | Time ranges with active state. |
| POST | `/api/analysis/vpc-sync-check` | any | ACL and binding differences between two peers. |

### Analysis — admin previews

Read-only, but admin-gated because they exist to produce a write.

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/analysis/acl-create-preview` | admin | CLI for a new ACL. |
| POST | `/api/analysis/reverse-direction-preview` | admin | Rules applied the wrong way round, and the corrected form. |
| POST | `/api/analysis/template-apply-preview` | admin | What applying a template would send. |

### Write — rules

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/write/rule-preview` | admin | Generate previews with the existing-access pre-check and sequence discovery. |
| POST | `/api/write/rule-check-existing` | admin | The pre-check on its own. |
| POST | `/api/write/rule-apply` | admin | Apply one rule to one switch, then verify by reading back. |
| POST | `/api/write/rule-edit` | admin | Replace one rule's text in place. |
| POST | `/api/write/rule-delete` | admin | Remove one rule, capturing the original line for the undo. |
| POST | `/api/write/summary-apply` | admin | Replace rules with a summary. Refused if the ACL changed since the suggestion. |

### Write — ACLs and interfaces

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/write/acl-create` | admin | Create an ACL. |
| POST | `/api/write/acl-delete` | admin | Delete an ACL, capturing its contents for the undo. |
| POST | `/api/write/acl-interface` | admin | Apply or remove an ACL on an interface. |
| POST | `/api/write/acl-interface-flip` | admin | Move an ACL applied in the wrong direction. |
| POST | `/api/write/reverse-direction-apply` | admin | Apply the corrected rules from the reverse-direction preview. |
| POST | `/api/write/acl-sync-preview` | admin | The exact difference between two VPC peers. |
| POST | `/api/write/acl-sync` | admin | Sync one peer to the other, touching only the differing sequences. |

### Write — object groups and time ranges

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/write/object-group-preview` | admin | CLI for creating or replacing a group. |
| POST | `/api/write/object-group-apply` | admin | Apply it. |
| POST | `/api/write/object-group-member-add` | admin | Add one member. |
| POST | `/api/write/object-group-member-edit` | admin | Change one member. |
| POST | `/api/write/object-group-member-delete` | admin | Remove one member. |
| POST | `/api/write/object-group-delete` | admin | Delete a group. Refused, naming the rules, while it is still referenced. |
| POST | `/api/write/time-range-preview` | admin | Build time-range CLI. |
| POST | `/api/write/time-range-apply` | admin | Apply to one switch. |
| POST | `/api/write/time-range-delete` | admin | Delete a time range. |

### Write — templates, save and undo

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/api/templates` | admin | Your templates and those shared with you. |
| POST | `/api/templates` | admin | Save one. |
| PUT | `/api/templates/{id}` | admin | Update one. |
| DELETE | `/api/templates/{id}` | admin | Delete one. |
| GET | `/api/templates/share-candidates` | admin | Admins a template can be shared with. |
| POST | `/api/write/template-apply` | admin | Apply a template. |
| POST | `/api/write/save-config` | admin | `copy running-config startup-config` on the selected switches. |
| POST | `/api/write/bulk-save-config` | admin | The same across several switches in one operation. |
| POST | `/api/write/undo` | admin | Run a returned undo set. |

### Access requests

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/requests` | any | Raise a request from a denied verdict. |
| GET | `/api/requests/mine` | any | Your own requests and their status. |
| POST | `/api/requests/mine/seen` | any | Acknowledge answered requests, so the same answer is not announced twice. |
| PUT | `/api/requests/{id}` | any | Amend your own remark while pending. |
| DELETE | `/api/requests/{id}` | any | Cancel your own. |
| GET | `/api/requests` | admin | The queue — excluding your own, and excluding switches you hold read-only or not at all. Super admins see everything. |
| POST | `/api/requests/{id}/done` | admin | Mark as done, with an optional note. |
| POST | `/api/requests/{id}/dismiss` | admin | Dismiss, with an optional note. |

### Terminal

| Method | Path | Role | Purpose |
|---|---|---|---|
| POST | `/api/terminal/sessions` | admin | Open a workspace for one or two switches. Refused for a switch without `terminal_access`. |
| DELETE | `/api/terminal/sessions/{id}` | admin | Close it. |
| WS | `/api/terminal/ws/{id}` | — | The session's websocket. Authorised by the session id issued above and checked against the `Origin` header; it carries no bearer token of its own. |

### Static

| Method | Path | Role | Purpose |
|---|---|---|---|
| GET | `/` | — | The SPA shell. |
| GET | `/{path:path}` | — | SPA fallback. Resolves the path and confirms it stays inside `frontend/`; anything under `/api/` returns 404 rather than falling through. |
| — | `/static/*` | — | Mounted `StaticFiles`, served `no-store`. |

### Status codes

| Code | Meaning |
|---|---|
| 200 | Success. A `success: false` body can still indicate a switch-level failure. |
| 400 | Validation failure. `detail` is a readable sentence. |
| 401 | Missing, invalid, expired or revoked token; or wrong credentials. |
| 403 | Insufficient privilege, untrusted host, or a write attempted on a read-only switch. |
| 404 | Resource not found, or unknown API path. |
| 409 | Conflict: a scan already running, or a role change while the target is still active. |
| 423 | Account locked. |
| 502 | Switch unreachable or rejected the command. Tagged `kind: "switch"`. |
| 503 | Health check only: the database could not be reached. |

