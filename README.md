# GIGACL

ACL management for Cisco IOS and NX-OS switches, over SSH, from a browser.

Ask whether a flow is permitted and get a per-switch verdict with the rule that
decided it. Add a rule and see the exact CLI before it is sent, with a one-click
undo after. Find rules that shadow each other, rules whose schedule expired,
rules pointing the wrong way, and ACLs that drifted apart across a VPC pair.

Nothing is written to a switch without a preview, an explicit confirmation, and
an audit entry. No write saves the running configuration — saving is always a
separate, deliberate action.

---

## Contents

- [What it does](#what-it-does)
- [Tested against](#tested-against)
- [Requirements](#requirements)
- [Install](#install)
- [First sign-in](#first-sign-in)
- [Adding switches](#adding-switches)
- [Running as a service on Linux](#running-as-a-service-on-linux)
- [Running on port 80 and 443](#running-on-port-80-and-443)
- [Configuration](#configuration)
- [Backup and restore](#backup-and-restore)
- [Upgrading](#upgrading)
- [Production checklist](#production-checklist)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Security](#security)
- [Contributing](#contributing)
- [Licence](#licence)

---

## What it does

**Read — every role, never touches a switch**

| | |
|---|---|
| **Access Checker** | Source, destination, protocol, port → PERMITTED / DENIED per switch, with the interface, ACL, direction and the exact rule that decided it. |
| **IP ACL Lookup** | One IP → which switch owns its gateway, on which interface, and every ACL applied there. |
| **ACL Viewer** | Every ACL, its rules colour-coded, where it is applied, and which rules have never matched. |
| **Redundancy** | Rules already covered by an earlier rule, paired with the rule that covers them — plus rules whose time range has expired and can never match again. |
| **Summary Suggester** | Rules that could collapse into one summary, showing exactly which lines it would replace. |
| **VPC Sync Check** | ACLs that have drifted between two VPC peers. |
| **Object Groups / Time Ranges** | What is defined, with members and live active/inactive state. |
| **Dashboard** *(admin and above)* | Changes, failures, active users, unsaved configs and per-switch findings over a chosen window — every number clicks through to the entries behind it. |

**Write — admins only**

Add a rule · remove a rule · apply a summary · create an ACL · create and edit
object groups and time ranges · fix a rule applied in the wrong direction ·
apply a saved template · save the running configuration.

Every one of them: preview the CLI → confirm → apply → verify by reading the
switch back → undo available → audit entry either way.

**Also**

An SSH terminal to a switch in the browser · access requests, so a read-only
user can ask an admin to open a path instead of filing a ticket · per-user
switch inventories with per-switch read/write grants · trusted-host allow lists
per user · lockout after failed sign-ins · an audit log with retention.

Full behavioural detail is in **[DOCUMENTATION.md](DOCUMENTATION.md)**.

---

## Tested against

| Platform | Model | Version |
|---|---|---|
| NX-OS | Nexus 92160YC-X | `nxos.9.3.16` |
| IOS / IOS-XE | Catalyst C9300 | `17.15.05` |

Other IOS and NX-OS releases are likely to work — the CLI surfaces used are
long-standing ones — but these two are what the behaviour was verified on,
including the VPC pairing logic, which was tested against a real peer pair.

The account GIGACL uses on a switch needs privilege level 15 for the write
features. Read-only features work with any account that can run `show`
commands; grant a switch read-only in GIGACL and no configuration command can
be issued against it at all.

---

## Requirements

- **Python 3.10 or newer** (developed and tested on 3.13)
- **Linux, macOS or Windows**
- Network reachability to the switches on TCP/22
- About 200 MB of disk for the virtual environment

No database server, no Node, no build step. Storage is SQLite in a single file;
the frontend is plain HTML, CSS and JavaScript served by the app itself.

---

## Install

### Linux / macOS

```bash
git clone https://github.com/thearcher13/GIGACL.git
cd GIGACL
./setup.sh
./start.sh
```

### Windows

```powershell
git clone https://github.com/thearcher13/GIGACL.git
cd GIGACL
powershell -ExecutionPolicy Bypass -File .\setup.ps1
.\start.bat
```

`setup` creates the virtual environment, installs the pinned dependencies from
[requirements.txt](requirements.txt), and writes a `.env`. It is safe to re-run;
it will not overwrite an existing `.env`.

`start` will run setup itself if it has not been run yet, so a first-timer can
go straight to `./start.sh`.

Then open **http://localhost:8000**.

To stop it: `Ctrl+C`, or `./stop.sh` (`stop.bat` on Windows) from another
terminal.

### Options

Both start scripts read the same environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address. Use `127.0.0.1` when a reverse proxy is in front. |
| `PORT` | `8000` | HTTP port. |
| `PROXY` | unset | Set to `1` behind a reverse proxy. See [port 80/443](#running-on-port-80-and-443). |
| `FORWARDED_ALLOW_IPS` | `127.0.0.1` | Which proxy address may set the forwarded client IP. |
| `RELOAD` | unset | Development only: restart on every backend save. |

```bash
PORT=8080 ./start.sh
```

---

## First sign-in

On the very first start, with no users in the database, GIGACL creates one
account:

| Username | Password |
|---|---|
| `admin` | `admin` |

> **Change this immediately after signing in.** It is a published password — it
> is written here, in the documentation, and in the source. Until it is changed,
> anyone who can reach the port is a super admin. The server prints a warning on
> every start while it is still in use, and the app itself will tell you.
>
> Change it under **Account → Change Password**. The new password must be at
> least 12 characters with an uppercase letter, a lowercase letter, a digit and
> a special character.

The seeded password deliberately fails that policy, so it cannot quietly become
a permanent one.

After that, create real accounts under **Users**. Roles:

| Role | Can |
|---|---|
| `user` | Read features only, on the switches granted to them. |
| `admin` | Read and write, plus manage `user` and `admin` accounts, and the dashboard for their own switches. |
| `super_admin` | Everything, including fleet-wide dashboard data and managing other super admins. |

---

## Adding switches

**Switch Management** (the button in the header) → **Add Switch**. You will
need the management IP, a username and password, and the platform (IOS or
NX-OS). GIGACL verifies the credentials by connecting before it saves them.

Switch passwords are encrypted at rest with the key in `.env` — see
[Backup and restore](#backup-and-restore), because that key and the database
have to travel together.

For a **VPC pair**, add both peers and then pair them; GIGACL will treat reads
as one logical unit and ask for confirmation on each peer separately for writes.

Each switch can be granted to a user **read-only** or **read-write**. The
read-only guard sits at the SSH layer, not in the interface: a read-only grant
cannot emit a configuration command even if the API is called directly.

---

## Running as a service on Linux

A unit file is included at [deploy/gigacl.service](deploy/gigacl.service).

**1. Put the app somewhere sensible and give it its own account.**

```bash
sudo mv GIGACL /opt/gigacl
sudo useradd --system --home /opt/gigacl --shell /usr/sbin/nologin gigacl
sudo chown -R gigacl:gigacl /opt/gigacl
```

Do not run it as root. The process holds switch credentials and opens SSH
sessions; it needs no privilege beyond reading its own directory.

**2. Install the dependencies as that account**, so the virtual environment is
owned by the user that will run it:

```bash
sudo -u gigacl /opt/gigacl/setup.sh
```

**3. Install the unit and edit the paths.**

```bash
sudo cp /opt/gigacl/deploy/gigacl.service /etc/systemd/system/gigacl.service
sudo nano /etc/systemd/system/gigacl.service   # check User, Group, WorkingDirectory, ExecStart
```

**4. Enable it. `enable` is the part that survives a reboot** — `start` alone
runs it now and forgets it:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now gigacl
```

**5. Check it.**

```bash
systemctl status gigacl
journalctl -u gigacl -f
curl -s localhost:8000/api/health     # {"status":"ok"}
```

Everyday commands:

```bash
sudo systemctl restart gigacl   # after upgrading
sudo systemctl stop gigacl
sudo systemctl disable gigacl   # stop starting at boot
```

The unit restarts the service if it crashes (`Restart=always`), waits up to 30
seconds for an in-flight switch command to finish on shutdown, and applies
systemd's standard hardening — a read-only view of the filesystem apart from
`/opt/gigacl`, no new privileges, a private `/tmp`. If one of the hardening
lines conflicts with your environment, delete it; they are all optional.

The unit binds `127.0.0.1` on the assumption that a reverse proxy is in front.
To serve directly with no proxy, change it to `0.0.0.0` and remove the two
`--proxy-headers` / `--forwarded-allow-ips` flags — with no proxy there is no
forwarded header worth trusting, and leaving them on would let a client claim
any address it liked.

### One worker, always

Both start scripts and the unit file pass `--workers 1`, deliberately. Live SSH
sessions, the browser terminal's channels and the per-user connection pool all
live in this process's memory, and SQLite takes one writer at a time. A second
worker would answer half the requests without any of that state. Scale by
giving the box more CPU, not more workers.

---

## Running on port 80 and 443

Ports below 1024 need privilege, and this process — which holds switch
credentials — should be the last thing on the box running as root. So put
something in front of it.

### Recommended: nginx in front

A config is included at [deploy/nginx-gigacl.conf](deploy/nginx-gigacl.conf).
It listens on 80 (redirecting to HTTPS) and 443, terminates TLS, and proxies to
GIGACL on `127.0.0.1:8000`.

```bash
sudo apt install nginx                              # or dnf install nginx
sudo cp /opt/gigacl/deploy/nginx-gigacl.conf /etc/nginx/sites-available/gigacl
sudo ln -s /etc/nginx/sites-available/gigacl /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nano /etc/nginx/sites-available/gigacl         # set server_name and the cert paths
sudo nginx -t && sudo systemctl reload nginx
```

On RHEL, Rocky and Alma there is no `sites-available` — put the file in
`/etc/nginx/conf.d/gigacl.conf` instead.

For a public hostname, Let's Encrypt will fill in the certificate lines:

```bash
sudo certbot --nginx -d gigacl.example.com
```

For an internal-only host, use your own CA or a self-signed pair and point
`ssl_certificate` / `ssl_certificate_key` at them.

Two things in that config are not optional:

- **The websocket headers.** The switch terminal is a websocket. Without
  `Upgrade` and `Connection` being passed through, it opens to a blank pane.
- **The forwarded-IP headers, paired with `--proxy-headers` on GIGACL.** GIGACL
  checks the caller's address against each user's trusted-host list and writes
  it into every audit entry. Behind a proxy without these, it sees the proxy —
  so a per-IP allow list matches nobody and the audit log records `127.0.0.1`
  for every user. `--forwarded-allow-ips 127.0.0.1` is what makes trusting the
  header safe: it is honoured only when the hop we are talking to is the local
  proxy, so a remote client cannot claim an address by setting the header
  itself.

If you are running from the start script rather than systemd, that means:

```bash
HOST=127.0.0.1 PROXY=1 ./start.sh
```

### Alternative: let the service bind 80/443 itself

No proxy, at the cost of terminating TLS in the app and granting it a
capability. Add to the `[Service]` section of the unit:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

and change `ExecStart` to:

```
ExecStart=/opt/gigacl/venv/bin/python -m uvicorn main:app \
    --host 0.0.0.0 --port 443 --workers 1 \
    --ssl-certfile /etc/ssl/certs/gigacl.pem \
    --ssl-keyfile  /etc/ssl/private/gigacl.key
```

The `gigacl` account must be able to read the key file. Nothing will then be
listening on port 80, so anyone typing a bare hostname gets a connection
refused — which is why the proxy is the recommendation.

### Alternative: redirect the port in the firewall

Keep the app on 8000 unprivileged and let the kernel do the mapping:

```bash
sudo firewall-cmd --permanent --add-forward-port=port=80:proto=tcp:toport=8000
sudo firewall-cmd --reload
```

or with nftables/iptables:

```bash
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8000
```

This gives you port 80 with no privilege and no proxy, but also no TLS, so it
suits a lab rather than production.

### Windows

Same shape: put IIS with **Application Request Routing**, or nginx for Windows,
in front of `127.0.0.1:8000`, and pass the same headers. Run `start.bat` with
`PROXY=1`. To have it start at boot, register it as a Windows service with
[NSSM](https://nssm.cc/) pointing at `venv\Scripts\python.exe` with the uvicorn
arguments from `start.bat`, working directory `backend`.

---

## Configuration

Settings live in `.env` at the project root. Copy [.env.example](.env.example)
if you do not have one.

| Key | Default | Meaning |
|---|---|---|
| `SECRET_KEY` | generated | Signs session tokens **and encrypts stored switch passwords**. Generated on first start and written back. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` | How long a sign-in lasts. |
| `DATABASE_URL` | `sqlite:///./giga_acl.db` | Relative paths resolve against `backend/`. |

`GIGACL_CORS_ORIGINS` (an environment variable, not a `.env` key) is only
needed if the frontend is ever hosted separately from the API. Same-origin is
the default and nothing legitimate needs otherwise.

Keep `.env` readable only by the service account — `chmod 600 .env`, which
`setup.sh` does for you. It is gitignored and must stay that way.

---

## Backup and restore

Two files matter, and **they must be kept together**:

| File | Why |
|---|---|
| `backend/giga_acl.db` | Users, switches, grants, templates, audit log. |
| `.env` | The key every stored switch password is encrypted with. |

A database restored next to a different `SECRET_KEY` will start, and users will
sign in, but every stored switch password will be undecryptable and will have to
be entered again. Back them up as a pair.

```bash
sudo systemctl stop gigacl
sudo -u gigacl cp /opt/gigacl/backend/giga_acl.db /backup/giga_acl.db.$(date +%F)
sudo -u gigacl cp /opt/gigacl/.env               /backup/env.$(date +%F)
sudo systemctl start gigacl
```

Stopping first is the honest way to copy a SQLite file that is being written to.

---

## Upgrading

```bash
sudo systemctl stop gigacl
cd /opt/gigacl && sudo -u gigacl git pull
sudo -u gigacl ./setup.sh          # picks up any dependency changes
sudo systemctl start gigacl
```

The schema migrates itself on start — new columns are added in place, and the
existing database is not replaced. Take the backup above first anyway.

---

## Production checklist

- [ ] `admin` / `admin` changed, and a named super admin account created
- [ ] Real accounts created; nobody sharing a login (the audit log names users)
- [ ] Switches granted read-only to anyone who does not need to write
- [ ] Running as a non-root account, not from a terminal
- [ ] `systemctl enable` done, and a reboot actually tested
- [ ] HTTPS in front, with `--proxy-headers` on and forwarded IPs verified in the audit log
- [ ] `.env` at mode 600 and backed up with the database
- [ ] Trusted-host allow lists set for users who should only sign in from known networks
- [ ] Audit-log retention set to something your policy agrees with
- [ ] A backup of `giga_acl.db` + `.env` on a schedule

---

## Troubleshooting

**`Port 8000 is already in use`** — something else has it, or a previous
instance is still running. `./stop.sh`, or `ss -ltnp | grep :8000`.

**The terminal opens to a blank pane behind a proxy** — the websocket headers
are missing. See [Running on port 80 and 443](#running-on-port-80-and-443).

**Every audit entry says `127.0.0.1`** — the app is behind a proxy without
`--proxy-headers`. Same section.

**`Authentication failed` when adding a switch** — GIGACL verifies credentials
by connecting before saving, so this is the switch refusing them. Check the
account works over plain SSH from the same host, and that the switch permits
SSH from this address.

**A backend change did nothing** — the server does not auto-reload. Restart it
(`sudo systemctl restart gigacl`, or `Ctrl+C` and `./start.sh`). A stale process
serving old code looks exactly like a bug in the new code.

**A frontend change did nothing** — hard-refresh. Static files are served
no-store and versioned with `?v=NN` in `index.html`, which is bumped when they
change.

**`The venv module is missing`** on Debian or Ubuntu — `sudo apt install
python3-venv`.

**The server says the admin password is still the published one** — it is.
Change it.

---

## Development

```bash
RELOAD=1 ./start.sh      # restart on every backend save
```

Run the test suite — 788 tests, no pytest needed:

```bash
cd backend && ../venv/bin/python -m unittest discover -s . -p "test_*.py" -q
```

The tests are the fastest way to find out whether a change to the ACL parser,
the directional logic or the write path broke something; several of them exist
because it did.

Layout:

```
backend/     FastAPI app, SSH layer, ACL parsing and analysis, 32 test modules
frontend/    index.html, app.js, style.css, terminal.js, vendored xterm.js
deploy/      systemd unit, nginx config
```

`DOCUMENTATION.md` is the reference for behaviour: the data model, the
directional logic, every write path's exact CLI, and the full API surface —
every route, checked against the code.

---

## Security

This app holds switch credentials and opens SSH sessions to production
hardware. If you deploy it:

- Change `admin` / `admin` before anything else. It is a published default —
  it is in this file, in the source, and in the documentation.
- Serve it over HTTPS. Session tokens live in `localStorage`.
- Run it as a non-root account, behind a reverse proxy, on a management network
  rather than the open internet.
- Grant switches read-only to anyone who does not need to write. That guard is
  at the SSH layer, so a read-only grant cannot emit a configuration command.
- Never commit `.env` or `backend/giga_acl.db`. Both are gitignored. `.env`
  holds the key that decrypts every stored switch password.

Found a security problem? Open an issue for anything low-risk, or email
iamirreza13@gmail.com for anything that should not be public first.

## Contributing

Issues and pull requests are welcome. Two things make a change easy to accept:

- Run the tests — `cd backend && ../venv/bin/python -m unittest discover -s . -p "test_*.py"`.
  788 of them, no pytest required.
- Read `DOCUMENTATION.md` for the subsystem you are touching. The directional
  logic and the sequence-number rules in particular are the way they are for
  reasons recorded there.

## Licence

MIT — see [LICENSE](LICENSE).
