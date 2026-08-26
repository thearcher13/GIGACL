# GIGACL — what it is, why it exists, and what it can do

A single-page write-up of the project: the problem it solves, how it works, the
complete feature set, and how to use each part. Intended to be readable by
someone who has never seen the repository.

---

## 1. The problem

Answering "is this traffic allowed?" on a Cisco estate means SSH-ing into a
switch, finding which interface owns the gateway, reading the ACL applied to it,
reading it in the right direction, and walking the rules in order until one
matches — remembering that object groups have to be expanded, that time ranges
may have expired, and that the answer differs depending on which side of the
flow you are standing on.

Then doing it again on the second switch, because the flow crosses two.

And adding a rule is worse: you have to pick a sequence number that lands
*before* the deny that would otherwise catch the traffic, get the direction
right, and type it into a production device with no preview and no undo.

That is what GIGACL automates. It is a web app that talks to IOS and NX-OS
switches over SSH and answers those questions — and makes those changes — with
a preview, a confirmation, a verification read-back, an undo, and an audit
entry for every one.

---

## 2. What was built

A FastAPI backend and a vanilla-JavaScript frontend, no build step, storing
everything in one SQLite file.

| | |
|---|---|
| Backend | Python 3.10+, FastAPI, SQLAlchemy, netmiko/paramiko over SSH |
| Frontend | Hand-written HTML/CSS/JS, served by the same process; xterm.js vendored for the terminal |
| Storage | SQLite, schema migrates itself in place on start |
| Tests | 788 tests across 32 modules, plain `unittest`, no external runner |
| Reference | `DOCUMENTATION.md` — data model, directional logic, every write path's CLI, and the full API surface |

Verified against **Nexus 92160YC-X (nxos.9.3.16)** and **Catalyst C9300
(17.15.05)**, including a real VPC peer pair.

### The design rules everything follows

1. **Reads never write.** The read-only guard is at the SSH layer, not in the
   interface — a read-only grant cannot emit a configuration command even if
   the API is called directly.
2. **No write is a surprise.** The exact CLI is shown, an explicit confirmation
   is required, and the generated syntax can be edited before it is sent.
3. **Applied is not the same as worked.** After a write, the switch is read back
   and success is reported only when the rule is actually present.
4. **Everything is undoable.** Every successful write returns an undo command
   set, shown in its own confirmation before it runs.
5. **Nothing saves the config.** Every change lands in the running
   configuration only. Saving is a separate, deliberate action, and the app
   tracks which switches have unsaved changes.
6. **Everything is logged**, success and failure, with the commands sent and
   the raw switch output.

---

## 3. Features

### 3.1 Access Checker — "is this flow permitted?"

Enter a source, a destination, a protocol and optionally a port. For every
switch in scope you get two verdicts — **source side** and **destination
side** — because a flow can be permitted leaving one VLAN and denied entering
another, and only reporting one of them is how people get the wrong answer.

Each verdict names the interface, the ACL, the direction, the reason, and the
exact rule that decided it. `N/A` means that switch does not own the gateway
for that address, stated plainly rather than implied.

Object groups are expanded, nested groups included. Time ranges are evaluated
against the switch's own clock, so a rule that exists but cannot currently
match is reported as such.

**Use it:** *Access Checker* → fill in source and destination → *Check*.

### 3.2 IP ACL Lookup — "what is protecting this address?"

One IP in, and for each switch: whether the gateway lives here, on which
interface, and every ACL applied to that interface with its rules expandable.
When no ACL is applied, it says so rather than showing an empty panel.

**Use it:** *IP ACL Lookup* → enter the IP → *Look up*.

### 3.3 ACL Viewer

Every ACL on the switch, or one by name. Collapsible panels with rule counts,
where each ACL is applied and in which direction, rules colour-coded by action,
and a marker on rules that have never matched. Admins get a remove button per
rule, which captures the original line first so the undo restores it verbatim
rather than approximating it.

**Use it:** *ACL Viewer* → leave the name blank for everything → *Load*.

### 3.4 Redundancy — dead weight in an ACL

Two categories, counted separately:

- **Redundant rules** — a rule already fully covered by an earlier rule, shown
  paired with the rule that covers it, so you can see why.
- **Dead schedule rules** — rules attached to a time range whose window has
  passed. They will never match again regardless of position.

Admins get *Remove all redundancies* to sweep a whole ACL, or one switch, in a
single reviewed operation.

**Use it:** *Redundancy* → blank for all ACLs → *Analyze*.

### 3.5 Summary Suggester

Finds runs of rules that could collapse into one summarised rule, and shows
exactly which lines it would replace — never a suggestion without its evidence.
Applying re-reads the ACL first and refuses if it changed since the suggestion
was generated. *Apply all summaries* does the whole set after one review.

**Use it:** *Summary Suggester* → *Analyze* → review → *Apply*.

### 3.6 VPC Sync Check

For a VPC peer pair, the ACLs that have drifted apart — present on one peer and
not the other, or present on both with different contents. This is the check
that is tedious by hand and the one that bites during a failover.

Admins can then **sync one peer to the other** from the same page, touching
only the sequence numbers that actually differ rather than rewriting the ACL.

**Use it:** pair the two switches in Switch Management, then *VPC Sync Check*.

### 3.7 Add ACL Rule

The most involved feature, and the reason for most of the logic.

- Source and destination as an IP, a subnet, `any`, or an object group.
- Protocol, and optionally a port, a range, or a port group.
- **Sequence numbers are chosen for you.** It finds free multiples of ten that
  land *before* the earliest deny that would otherwise catch the traffic —
  because a rule placed after that deny is a rule that does nothing.
- **Direction is worked out from the topology**, not guessed, using the same
  logic the Access Checker uses.
- **Existing access is checked first.** If the traffic is already permitted,
  it tells you instead of adding a duplicate.
- The generated CLI is shown and can be edited; the edit is re-validated.
- Permit only. Deny is rejected in the browser and again at the API.
- Undo is `no <sequence>` in the same ACL.

On a VPC pair, each peer is confirmed separately.

**Use it:** *Add ACL Rule* → fill in the flow → *Generate preview* → review the
CLI → *Apply*.

### 3.8 Other write features

| Feature | What it does |
|---|---|
| **Add ACL** | Creates a new ACL, and can attach or detach it on an interface. Deleting an ACL is supported too. |
| **Object Groups** | Create and edit address and port groups. Group type comes from platform-specific headers, never guessed from member syntax. |
| **Time Ranges** | Create and edit periodic and absolute ranges, with a live ACTIVE NOW / NOT ACTIVE badge. |
| **Reverse Direction** | Finds rules applied in the wrong direction and offers the corrected form. |
| **Templates** | Save a rule pattern and apply it later; shareable with other admins. |
| **Save Config** | The only thing that writes to startup-config. Saves both peers of a VPC pair together. |

### 3.9 Access requests

A read-only user who hits a denial can raise a request describing the path they
need, instead of writing a ticket in another system. Admins see a queue,
open the request straight into a pre-filled Add ACL Rule form, and mark it done.

The queue is scoped honestly: a request is not shown to an admin who holds that
switch read-only, because they could not act on it either way — the only thing
an unactionable row offers is a dead end. Super admins see everything.

### 3.10 Switch terminal

A real SSH session to a switch in the browser, with the same read-only guard as
everything else. Two panes side by side for a VPC pair, with an optional synced
input mode.

### 3.11 Dashboard (admin and above)

Over a window you choose: changes made, rules added and removed, failed
operations, failed sign-ins, active users, switch count, unsaved
configurations. A regular admin sees their own logs and switches here; a super
admin sees everyone's. Every tile clicks through to the entries behind it, and
a bar strip by day or hour narrows everything to one period when clicked.

Plus **Switch analyze** — a per-switch table of the last scan: redundant rules,
wrong-direction rules, summarisable rules, dead schedules, VPC sync state and
TCAM utilisation, each count linking into the page that shows the detail.

### 3.12 Users, access control and audit

| | |
|---|---|
| **Roles** | `user` (read only), `admin` (read, write, manage users and admins), `super_admin` (everything, including other super admins). |
| **Per-switch grants** | Each user has their own switch inventory; each switch is granted read-only or read-write. |
| **Trusted hosts** | A per-user IP/prefix allow list — sign-in is refused from anywhere else. |
| **Lockout** | Three failed attempts in five minutes locks the account for five minutes, answered with HTTP 423 and the remaining time. |
| **Passwords** | 12 characters minimum, upper, lower, digit and special, enforced at the API as well as in the browser. |
| **Token revocation** | A role change or a password reset invalidates the existing token immediately rather than leaving it valid for the rest of its eight hours. |
| **Audit log** | Every action with the user, the address, the commands sent and the raw output, filterable, exportable, with configurable retention. |
| **Credentials at rest** | Switch passwords encrypted with a key generated on first run and kept out of the repository. Signing and encryption keys are derived separately, so a leaked signing key reveals nothing about credentials. |

### 3.13 Themes

Six: Midnight, Slate, Carbon, Daylight, Glacier and Evermore. Chosen per user
and remembered.

---

## 4. How the hard parts work

**Direction.** An ACL applied inbound on the interface that owns the source
gateway sees the flow one way; the same ACL applied outbound on the destination
side sees it the other. GIGACL works out which interface owns which gateway
from `show ip route`, then evaluates each ACL in the direction it is actually
applied. This is what makes the two-sided verdict possible, and it is the same
code path the rule generator uses to build correct syntax.

**Object groups.** Group type is taken from platform-specific headers only —
NX-OS `IPv4 address object-group` / `Protocol port object-group`, IOS `Network
object group` / `Service object group`. Member syntax is never used to infer
the type, and headers from the other platform are ignored, because a group
misclassified as the wrong type generates a rule the switch rejects. Nested
groups are resolved.

**Sequence selection.** A permit placed after the deny that would catch the
traffic is a permit that does nothing. So every candidate sequence is checked
against the earliest *effective* deny — with object groups involved, the whole
generated rule is compared structurally against the ordered ACL rather than by
address arithmetic. If no multiple of ten is free below that deny, single
digits are tried; if there is no lower sequence at all, the preview fails
rather than producing a rule that would silently be inert.

**Performance.** Reads across a VPC pair run in parallel, and each request
gets one SSH read cache, so a preview that used to make twenty round trips —
thirteen of them fetching the same handful of time ranges one at a time — now
makes a fraction of that. Add Rule went from about 12 seconds to about 5, and
a VPC pair from about 24 to about 5.

---

## 5. Deployment shape

Runs from a script on Linux, macOS or Windows; as a systemd service on Linux
that survives a reboot; behind nginx on 80/443 with TLS. Single worker,
deliberately — live SSH sessions and the terminal's channels live in process
memory and SQLite takes one writer at a time.

Full instructions, including the systemd unit, the nginx config and the
reverse-proxy caveats, are in **[README.md](README.md)**.

---

## 6. Getting started in five minutes

```bash
./setup.sh && ./start.sh          # Linux/macOS
```
```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1; .\start.bat   # Windows
```

1. Open <http://localhost:8000>.
2. Sign in as **`admin` / `admin`** — then **change that password immediately**,
   under *Account → Change Password*. It is a published default; until it is
   changed anyone who can reach the port is a super admin.
3. *Switch Management* → *Add Switch*. Credentials are verified by connecting
   before they are stored. Pair VPC peers here.
4. *Access Checker* → ask it something you already know the answer to. That is
   the fastest way to confirm the inventory and the direction logic agree with
   reality.
5. Create real accounts under *Users*, grant switches read-only to anyone who
   does not need to write, and set trusted hosts where it applies.

---

## 7. Known limits

Recorded honestly, because a tool that touches production hardware should be
clear about where it stops.

| Limit | Detail |
|---|---|
| IPv4 only | Every address validator is `IPv4Address`/`IPv4Network`. IPv6 ACLs are neither parsed nor generated. |
| Verified platforms | Nexus 92160YC-X `nxos.9.3.16` and Catalyst C9300 `17.15.05`. Other IOS/NX-OS releases are likely to work but are unverified. |
| SQLite, single worker | In-process SSH sessions and one writer at a time. Sized for an operations team, not hundreds of concurrent users. |
| Tokens in `localStorage` | Serve it over HTTPS. |
| Undo depth | One step per operation, offered immediately after it. There is no multi-step history. |
| Very large ACLs | Above 3000 rules a sweep skips the quadratic redundancy and summary passes and reports the switch as partial. |
| Summary scope | Only source addresses are collapsed, and only for rules without object groups. |
| Dashboard health | A snapshot from the last scan, never live. Every row shows its age. |
| Time-range status | Depends on the switch reporting `(active)`/`(inactive)`; otherwise reported as unknown. |
| Hit counters | "Never matched" markers inherit whatever the switch's counters have been through since the last clear. |
| Lockout scope | Per account, not per source IP. A locked account is locked everywhere. |
| Token revocation | Per account. A role change or password reset invalidates earlier tokens; there is no per-token blocklist. |

### Deliberately not built

Deny-rule creation, config diffing or backup, email and webhook notifications,
LDAP or RADIUS, and multi-tenancy beyond per-user ownership. There is no
background scheduler either — the dashboard sweep runs when someone presses
Scan now, and the only recurring task in the backend is the six-hourly
audit-log retention check.

---

## 8. Where things are

| | |
|---|---|
| Install and run | `README.md` |
| Behaviour reference | `DOCUMENTATION.md` — data model, directional logic, every write path's CLI, and all 101 API routes |
| Licence | MIT |
