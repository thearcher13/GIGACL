"""
Switch-facing service layer: resolution, validation and command execution.
Keeps route handlers thin.
"""
import re
import threading
from contextlib import contextmanager
from typing import List, Tuple, Optional, Dict, Any
from fastapi import HTTPException
from sqlalchemy.orm import Session

from database import Switch, TYPE_NEXUS, ACCESS_READ, ACCESS_WRITE
from switch_utils import get_switch_and_password
import ssh_manager
import acl_parser
from validators import ValidationError


class SwitchTarget:
    """A resolved switch plus its decrypted SSH password and optional enable password."""
    __slots__ = ("sw", "password", "ssh_username", "enable_password",
                 "_read_cache", "_read_lock")

    def __init__(self, sw: Switch, password: str, ssh_username: str, enable_password: Optional[str] = None):
        self.sw = sw
        self.password = password
        self.ssh_username = ssh_username
        self.enable_password = enable_password
        # Off unless an endpoint opts in with cached_reads(). See show().
        self._read_cache = None
        self._read_lock = threading.Lock()

    # convenience passthroughs
    @property
    def id(self):        return self.sw.id
    @property
    def ip(self):        return self.sw.ip_address
    @property
    def label(self):     return self.sw.hostname or self.sw.ip_address
    @property
    def type(self):      return (self.sw.switch_type or "ios").lower()
    @property
    def use_enable(self): return bool(self.sw.use_enable)
    @property
    def is_nexus(self):  return self.type == TYPE_NEXUS
    @property
    def access_level(self): return (self.sw.access_level or ACCESS_WRITE).lower()
    @property
    def can_write(self):  return self.access_level != ACCESS_READ


def resolve_targets(switch_ids: List[int], username: str,
                    db: Session, require_write: bool = False) -> List[SwitchTarget]:
    """
    Resolve switch ids to targets, enforcing the multi-select rules:
      · at most 2 switches
      · multi-select requires ALL selected switches to be Nexus
    username parameter is the owner username (current user), not SSH username

    `require_write` refuses read-only switches up front. Previews need it:
    they send nothing to the device, so the guard inside configure() never
    sees them, yet they exist only to stage a change.
    """
    if not switch_ids:
        raise HTTPException(400, "No switch is selected. Choose a switch first.")

    # de-duplicate while preserving order
    seen, ordered = set(), []
    for sid in switch_ids:
        if sid not in seen:
            seen.add(sid)
            ordered.append(sid)

    if len(ordered) > 2:
        raise HTTPException(400, "You can select at most two switches (a VPC pair).")

    targets = []
    for sid in ordered:
        sw, pw, enable_pw = get_switch_and_password(sid, username, None, db)
        ssh_username = sw.ssh_username or username  # Default to owner username if not set
        targets.append(SwitchTarget(sw, pw, ssh_username, enable_pw))

    if require_write:
        for t in targets:
            require_write_access(t)

    if len(targets) > 1:
        non_nexus = [t.label for t in targets if not t.is_nexus]
        if non_nexus:
            raise HTTPException(
                400,
                "Only Nexus switches can be managed together. "
                f"Not a Nexus switch: {', '.join(non_nexus)}. "
                "Deselect it and choose a single switch instead."
            )
    return targets


# ── command wrappers ──

class ReadOnlyAccessError(Exception):
    """Raised when a read-only switch is asked to change something."""


def require_write_access(t: SwitchTarget):
    """
    Refuse anything that would modify a read-only switch.

    Enforced here, at the point commands are actually sent, rather than only
    at each endpoint: there are more than forty write endpoints and a missed
    check on any one of them would be a silent hole. Endpoints check as well,
    so the caller gets a clear message instead of a failure deep in the stack.
    """
    if not t.can_write:
        raise ReadOnlyAccessError(
            f"You have read-only access to {t.label}. "
            "Ask the super admin who gave you this switch for write access.")



@contextmanager
def cached_reads(targets):
    """
    Answer repeated `show` commands from memory for the duration of one
    request.

    Off by default and opt-in per endpoint, because a switch's configuration
    is only stable within a single read. Anything that writes and then reads
    back to verify must not use this -- it would be shown the state from
    before its own change.

    The win is real: one Add ACL Rule preview issued twenty SSH round trips,
    of which thirteen were `show time-range <name>` one name at a time, with
    one range fetched three times, plus `show object-group` and the ACL itself
    fetched twice each. At half a second per round trip that is most of the
    twelve seconds the preview took.
    """
    for t in targets:
        t._read_cache = {}
    try:
        yield
    finally:
        for t in targets:
            t._read_cache = None


def show(t: SwitchTarget, username: str, command: str, timeout: float = 25, 
         enable_password: Optional[str] = None) -> str:
    """Execute a show command. username param kept for backwards compatibility but ssh_username from target is used."""
    cache = t._read_cache
    if cache is not None:
        with t._read_lock:
            if command in cache:
                return cache[command]
    # Use enable password from target if not explicitly provided
    ep = enable_password if enable_password is not None else t.enable_password
    out = ssh_manager.run_command(t.ssh_username, t.ip, t.password, command,
                                  t.type, timeout=timeout,
                                  use_enable=t.use_enable,
                                  enable_password=ep)
    # Deliberately outside the lock: two threads racing the same uncached
    # command both fetch it, which wastes one round trip. Holding the lock
    # across the SSH call instead would serialise every read on the switch
    # and undo the parallelism this is meant to speed up.
    if cache is not None:
        with t._read_lock:
            cache[command] = out
    return out


def run_with_confirm(t: SwitchTarget, username: str, command: str, timeout: float = 60,
                     enable_password: Optional[str] = None) -> str:
    """Execute a command that requires confirmation (like copy commands)."""
    # Only used for 'copy running-config startup-config', which changes the
    # device's stored configuration and so counts as a write.
    require_write_access(t)
    ep = enable_password if enable_password is not None else t.enable_password
    return ssh_manager.run_command_with_confirm(t.ssh_username, t.ip, t.password, command,
                                                t.type, timeout=timeout,
                                                use_enable=t.use_enable,
                                                enable_password=ep)


def configure(t: SwitchTarget, username: str, commands: List[str],
              timeout: float = 30, enable_password: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
    """
    Run config commands. Returns (ok, raw_output, error_message).
    username param kept for backwards compatibility but ssh_username from target is used.
    """
    require_write_access(t)
    try:
        # Use enable password from target if not explicitly provided
        ep = enable_password if enable_password is not None else t.enable_password
        out = ssh_manager.run_config(t.ssh_username, t.ip, t.password, commands,
                                     t.type, use_enable=t.use_enable,
                                     enable_password=ep,
                                     timeout=timeout)
    except ssh_manager.SSHError as e:
        return False, "", str(e)
    err = ssh_manager.detect_switch_error(out)
    return (err is None), out, err


# ── higher level fetch helpers ──

def list_acl_names(t: SwitchTarget, username: str) -> List[str]:
    out = show(t, username, "show ip access-lists", timeout=40)
    return sorted(set(re.findall(r"IP access list\s+(\S+)", out, re.IGNORECASE)))


def list_all_acl_rules(t: SwitchTarget, username: str) -> Dict[str, List[str]]:
    """
    Fetch every ACL and its rules in one command instead of one
    'show ip access-lists <name>' round trip per ACL.
    """
    out = show(t, username, "show ip access-lists", timeout=40)
    return acl_parser.parse_all_acl_rules(out)


def list_all_acls(t: SwitchTarget, username: str) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """
    Fetch every ACL's rules AND its standard/extended kind from a single
    command. Used by the View ACL page so it can render a kind-aware CLI
    preview instead of guessing 'extended' for every IOS ACL.
    """
    out = show(t, username, "show ip access-lists", timeout=40)
    return acl_parser.parse_all_acl_rules(out), acl_parser.parse_acl_kinds(out)


def get_acl_kind(t: SwitchTarget, username: str, acl_name: str) -> str:
    """
    Reliable standard/extended detection for one IOS ACL. Reads the
    unfiltered 'show ip access-lists' listing rather than the name-filtered
    form, which can omit the Standard/Extended prefix on some platforms.
    """
    out = show(t, username, "show ip access-lists", timeout=40)
    return acl_parser.parse_acl_kinds(out).get(acl_name, "extended")


def get_acl_rules(t: SwitchTarget, username: str, acl_name: str) -> Tuple[str, List[str]]:
    out = show(t, username, f"show ip access-lists {acl_name}", timeout=25)
    return out, acl_parser.parse_acl_lines(out)


def get_interface_acls(t: SwitchTarget, username: str, iface: str) -> List[Dict[str, str]]:
    out = show(t, username, f"show running-config interface {iface}", timeout=20)
    return acl_parser.parse_interface_acl(out)


def map_acl_interfaces(t: SwitchTarget, username: str) -> Dict[str, List[Dict[str, str]]]:
    """Map every ACL name → the interfaces (and directions) it is applied to."""
    out = show(t, username, "show running-config", timeout=90)
    return acl_parser.parse_acl_interface_map(out)


def get_vlan_acl_bindings_and_subnets(t: SwitchTarget, username: str):
    """
    One 'show running-config' pass (kept self-contained from
    map_acl_interfaces() above, on purpose — this feeds the Redundancy
    Checker's wrong-direction check and shouldn't share a refactor risk
    with VPC Sync Check's already-tested interface mapping) for VLAN
    interfaces only: which ACLs are applied where, and each VLAN's own
    configured subnet.
    """
    out = show(t, username, "show running-config", timeout=90)
    return acl_parser.parse_vlan_acl_bindings_and_subnets(out)


def get_object_groups(t: SwitchTarget, username: str) -> List[Dict[str, Any]]:
    """
    Fetch and classify object groups from the platform's ``show object-group``
    headers. Group member syntax is never used to infer the type.
    """
    try:
        out = show(t, username, "show object-group", timeout=40)
    except ssh_manager.SSHError:
        return []
    if ssh_manager.detect_switch_error(out):
        return []
    groups = acl_parser.parse_object_groups(out, t.type)
    return sorted(groups, key=lambda g: (g["kind"], g["name"].lower()))


def get_time_ranges(t: SwitchTarget, username: str) -> List[Dict[str, Any]]:
    """Fetch configured time-ranges and their active state."""
    ranges: Dict[str, Dict[str, Any]] = {}
    
    # Try primary command: show time-range
    try:
        out = show(t, username, "show time-range", timeout=30)
        if not ssh_manager.detect_switch_error(out):
            for r in acl_parser.parse_time_ranges(out):
                ranges[r["name"]] = r
    except ssh_manager.SSHError:
        pass

    # Fallback: try running-config if we got nothing
    if not ranges:
        try:
            out = show(t, username, "show running-config | section time-range", timeout=30)
            for name in acl_parser.parse_time_range_names(out):
                ranges.setdefault(name, {"name": name, "status": "unknown", "entries": []})
        except ssh_manager.SSHError:
            pass
            
    return sorted(ranges.values(), key=lambda r: r["name"].lower())


def resolve_addr_group(t: SwitchTarget, username: str, group: str) -> List[str]:
    for item in get_object_groups(t, username):
        if item["name"].lower() == group.lower() and item["kind"] == "address":
            return acl_parser.parse_object_group_addresses("\n".join(item["members"]))
    return []


def resolve_port_group(t: SwitchTarget, username: str, group: str):
    for item in get_object_groups(t, username):
        if item["name"].lower() == group.lower() and item["kind"] == "port":
            return acl_parser.parse_object_group_services("\n".join(item["members"]))
    return []


def time_range_active(t: SwitchTarget, username: str, name: str) -> bool:
    """
    Check if a time-range is currently active.
    Returns True if active, False if inactive or cannot be determined.
    Uses the same parsing logic as get_time_ranges() for consistency.
    """
    try:
        out = show(t, username, f"show time-range {name}", timeout=20)
        if ssh_manager.detect_switch_error(out):
            # If there's an error querying the time-range, we cannot determine status
            return False
        
        # Use the same parse_time_ranges() function that the display uses
        # This ensures consistency between what's shown and what's evaluated
        ranges = acl_parser.parse_time_ranges(out)
        
        # Find the specific time-range we're looking for
        for r in ranges:
            if r["name"] == name:
                return r["status"] == "active"
        
        # If we didn't find it in the parsed output, return False
        return False
    except ssh_manager.SSHError:
        return False
