"""
Input validation helpers.
Every function raises ValidationError with a clear, user-facing message.
"""
import ipaddress
import re
from typing import Optional, List

from acl_parser import ICMP_TYPES


class ValidationError(Exception):
    """Raised when user input fails validation."""
    pass


# ── Safety: block characters that could chain extra CLI commands ──
_CLI_UNSAFE = re.compile(r"[;\|&`$\r\n<>]")

# Cisco identifiers: ACL names, object-group names, time-range names
_IDENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-\.]{0,63}$")
_OBJECT_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-\./]{0,63}$")


def check_cli_safe(value: str, field: str) -> str:
    """Reject anything that could inject additional switch commands."""
    if value is None:
        return ""
    if _CLI_UNSAFE.search(value):
        raise ValidationError(
            f"{field} contains characters that are not allowed "
            f"(; | & ` $ < > or newlines)."
        )
    return value.strip()


def validate_identifier(value: str, field: str) -> str:
    """Validate an ACL / object-group / time-range name."""
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    if not _IDENT_RE.match(v):
        raise ValidationError(
            f"{field} '{v}' is not valid. Use letters, digits, dot, dash or "
            f"underscore (max 64 characters, must start with a letter or digit)."
        )
    return v


def validate_remark(value: Optional[str]) -> Optional[str]:
    """Validate an optional, single-line ACL remark."""
    if value is None or not str(value).strip():
        return None
    remark = check_cli_safe(str(value), "Remark")
    if len(remark) > 100:
        raise ValidationError("Remark is too long (maximum 100 characters).")
    return remark


def validate_object_group_name(value: str, field: str) -> str:
    """Validate an object-group name, including NX-OS names containing '/' ."""
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    if not _OBJECT_GROUP_RE.match(v):
        raise ValidationError(
            f"{field} '{v}' is not valid. Use letters, digits, dot, dash, "
            "underscore or slash (max 64 characters).")
    return v


def validate_ip(value: str, field: str = "IP address") -> str:
    """Validate a single host IP (no prefix)."""
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        raise ValidationError(f"{field} '{v}' is not a valid IPv4 address.")
    return v


def validate_ip_or_network(value: str, field: str,
                           allow_any: bool = True,
                           allow_group: bool = True) -> str:
    """
    Accepts:
      · any
      · addrgroup NAME
      · 10.0.0.1
      · 10.0.0.0/24
    Returns the normalised string.
    """
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")

    low = v.lower()

    if low == "any":
        if not allow_any:
            raise ValidationError(f"{field} cannot be 'any' here.")
        return "any"

    if low.startswith("addrgroup"):
        if not allow_group:
            raise ValidationError(f"{field} cannot be an object-group here.")
        parts = v.split(None, 1)
        if len(parts) != 2 or not parts[1].strip():
            raise ValidationError(
                f"{field}: object-group syntax must be 'addrgroup NAME'."
            )
        name = validate_object_group_name(parts[1].strip(),
                                          f"{field} group name")
        return f"addrgroup {name}"

    try:
        if "/" in v:
            net = ipaddress.IPv4Network(v, strict=False)
            return str(net)
        ipaddress.IPv4Address(v)
        return v
    except ValueError:
        raise ValidationError(
            f"{field} '{v}' is not valid. Use an IP (10.0.0.1), "
            f"a subnet (10.0.0.0/24), 'any', or 'addrgroup NAME'."
        )


def validate_prefix(value: str, field: str) -> str:
    """
    Validate an NX-OS object-group address member: 'A.B.C.D/LEN' or a bare IP
    (treated as /32, i.e. a single host).
    """
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    try:
        net = ipaddress.IPv4Network(v, strict=False)
    except ValueError:
        raise ValidationError(
            f"{field} is not a valid network prefix. Use A.B.C.D/LEN or a bare IP.")
    return str(net)


def validate_object_group_ip(value: str, field: str) -> str:
    """
    Validate an IOS object-group address member.
    Accepts a bare IP (treated as /32) or a CIDR subnet. No 'any', no group syntax.
    """
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    try:
        if "/" in v:
            net = ipaddress.IPv4Network(v, strict=False)
            return str(net)
        ipaddress.IPv4Address(v)
        return v
    except ValueError:
        raise ValidationError(
            f"{field} is not valid. Use a network address or select an object group.")


def validate_port_only(value: str, field: str = "Port") -> str:
    """
    Validate a raw port or port range for an object-group port member.
    Accepts '80' or '8080-9000'. No 'portgroup' keyword.
    """
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")

    def _one(p: str) -> int:
        p = p.strip()
        if not p.isdigit():
            raise ValidationError(f"{field} must be a number between 1 and 65535.")
        n = int(p)
        if not (1 <= n <= 65535):
            raise ValidationError(f"{field} must be a number between 1 and 65535.")
        return n

    if "-" in v:
        lo_s, _, hi_s = v.partition("-")
        lo, hi = _one(lo_s), _one(hi_s)
        if lo >= hi:
            raise ValidationError(
                f"{field} range is invalid: the first port must be lower than the second."
            )
        return f"{lo}-{hi}"

    return str(_one(v))


# Named port keywords Cisco IOS accepts in place of a number, per protocol
# (object-group service / ACL port operators). NX-OS does not accept these —
# port members there must be numeric.
_IOS_TCP_PORTS = {
    "bgp", "chargen", "cmd", "daytime", "discard", "domain", "echo", "exec",
    "finger", "ftp", "ftp-data", "gopher", "hostname", "ident", "irc",
    "klogin", "kshell", "login", "lpd", "msrpc", "nntp", "onep-plain",
    "onep-tls", "pim-auto-rp", "pop2", "pop3", "smtp", "sunrpc", "tacacs",
    "talk", "telnet", "time", "uucp", "whois", "www",
}
_IOS_UDP_PORTS = {
    "biff", "bootpc", "bootps", "discard", "dnsix", "domain", "echo",
    "isakmp", "mobile-ip", "nameserver", "netbios-dgm", "netbios-ns",
    "netbios-ss", "non500-isakmp", "ntp", "pim-auto-rp", "rip", "ripv6",
    "snmp", "snmptrap", "sunrpc", "syslog", "tacacs", "talk", "tftp",
    "time", "who", "xdmcp",
}
_IOS_TCPUDP_PORTS = {
    "discard", "domain", "echo", "pim-auto-rp", "sunrpc", "syslog",
    "tacacs", "talk",
}
_IOS_NAMED_PORTS = {"tcp": _IOS_TCP_PORTS, "udp": _IOS_UDP_PORTS,
                    "tcp-udp": _IOS_TCPUDP_PORTS}


def validate_ios_port_spec(value: str, protocol: str, field: str = "Port") -> str:
    """
    Validate an IOS object-group port member: a number, a numeric range, or
    (for a single port) a protocol-appropriate named keyword such as 'www'.
    """
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is required.")
    named = _IOS_NAMED_PORTS.get(protocol, set())

    def _numeric(p: str) -> Optional[str]:
        p = p.strip()
        if not p.isdigit():
            return None
        n = int(p)
        if not (1 <= n <= 65535):
            raise ValidationError(f"{field} must be a number between 1 and 65535.")
        return str(n)

    # Only a strictly numeric 'LO-HI' is a range — several valid keywords
    # (e.g. 'ftp-data', 'pim-auto-rp') contain a hyphen themselves and must
    # not be mistaken for one.
    range_m = re.match(r"^(\d+)-(\d+)$", v)
    if range_m:
        lo, hi = _numeric(range_m.group(1)), _numeric(range_m.group(2))
        if int(lo) >= int(hi):
            raise ValidationError(
                f"{field} range is invalid: the first port must be lower than the second.")
        return f"{lo}-{hi}"
    if "-" in v and v.lower() not in named:
        raise ValidationError(
            f"{field} must use numeric ports for a range (e.g. 8080-9000); "
            f"named keywords cannot be used in a range.")

    numeric = _numeric(v)
    if numeric is not None:
        return numeric
    if v.lower() in named:
        return v.lower()
    raise ValidationError(
        f"{field} must be a number between 1 and 65535, or a valid "
        f"{protocol.upper()} keyword.")


def validate_protocol_only(value: str) -> str:
    v = (value or "").strip().lower()
    if v not in ("tcp", "udp", "tcp-udp"):
        raise ValidationError(
            f"Protocol '{value}' is not supported. Choose TCP, UDP, or TCP-UDP."
        )
    return v


def validate_object_group_member_line(value: str, field: str = "Member") -> str:
    """Validate one manually edited object-group member line (no permit/deny requirement)."""
    v = check_cli_safe(value or "", field)
    if not v:
        raise ValidationError(f"{field} is empty.")
    if len(v) > 200:
        raise ValidationError(f"{field} is too long (max 200 characters).")
    return v


def validate_protocol(value: str) -> str:
    v = (value or "").strip().lower()
    allowed = {"all", "ip", "tcp", "udp", "icmp"}
    if v not in allowed:
        raise ValidationError(
            f"Protocol '{value}' is not supported. Choose one of: "
            f"All, TCP, UDP, ICMP."
        )
    return "all" if v == "ip" else v


def validate_port_spec(value: Optional[str], protocol: str) -> Optional[str]:
    """
    Accepts: None, '80', '8080-9000', 'portgroup NAME', or a named port.
    Only valid for tcp/udp.
    """
    if value is None or not str(value).strip():
        return None
    v = check_cli_safe(str(value), "Port")

    if protocol not in ("tcp", "udp"):
        raise ValidationError(
            "A port can only be specified for TCP or UDP. "
            "Clear the port field or change the protocol."
        )

    if v.lower().startswith("portgroup"):
        parts = v.split(None, 1)
        if len(parts) != 2 or not parts[1].strip():
            raise ValidationError("Port group syntax must be 'portgroup NAME'.")
        name = validate_object_group_name(parts[1].strip(), "Port group name")
        return f"portgroup {name}"

    def _one(p: str) -> int:
        p = p.strip()
        if not p.isdigit():
            raise ValidationError(
                f"Port '{p}' must be a number between 1 and 65535."
            )
        n = int(p)
        if not (1 <= n <= 65535):
            raise ValidationError(f"Port {n} is out of range (1–65535).")
        return n

    if "-" in v:
        lo_s, _, hi_s = v.partition("-")
        lo, hi = _one(lo_s), _one(hi_s)
        if lo >= hi:
            raise ValidationError(
                f"Port range {lo}-{hi} is invalid: the first port must be "
                f"lower than the second."
            )
        return f"{lo}-{hi}"

    return str(_one(v))


def validate_icmp_type(value: Optional[str], protocol: str) -> Optional[str]:
    """
    Accepts: None/empty (meaning all ICMP types) or one of ICMP_TYPES.
    Only valid when protocol is icmp.
    """
    if value is None or not str(value).strip():
        return None
    v = check_cli_safe(str(value), "ICMP type").strip().lower()

    if protocol != "icmp":
        raise ValidationError(
            "An ICMP type can only be specified when the protocol is ICMP. "
            "Clear the ICMP type or change the protocol."
        )
    if v not in ICMP_TYPES:
        raise ValidationError(
            "ICMP type must be one of: echo, echo-reply, unreachable, "
            "administratively-prohibited, packet-too-big, time-exceeded, "
            "redirect, traceroute."
        )
    return v


def validate_established(value: Optional[bool], protocol: str,
                         port: Optional[str]) -> bool:
    """
    'established' matches only TCP segments with ACK/RST set — return
    traffic inside an already-open session, never the initial SYN. It is
    offered alongside a specific service port, so both conditions are
    enforced here rather than trusted from the form.
    """
    if not value:
        return False
    if protocol != "tcp":
        raise ValidationError(
            "The 'established' keyword only applies to TCP. Change the protocol "
            "to TCP or clear 'established'."
        )
    if not port or not str(port).strip():
        raise ValidationError(
            "The 'established' keyword needs a service port. Specify the port or "
            "clear 'established'."
        )
    return True


def validate_sequence(value) -> Optional[int]:
    if value is None or str(value).strip() == "":
        return None
    s = str(value).strip()
    if not s.isdigit():
        raise ValidationError("Sequence number must be a whole number.")
    n = int(s)
    if not (1 <= n <= 4294967294):
        raise ValidationError("Sequence number must be between 1 and 4294967294.")
    return n


def validate_vlan_interface(value: str) -> str:
    """Accept a VLAN number or Cisco Vlan interface name."""
    raw = check_cli_safe(value or "", "VLAN")
    match = re.fullmatch(r"(?:vlan\s*)?(\d{1,4})", raw, re.IGNORECASE)
    if not match:
        raise ValidationError("VLAN must be a number such as 748 or Vlan748.")
    number = int(match.group(1))
    if not 1 <= number <= 4094:
        raise ValidationError("VLAN number must be between 1 and 4094.")
    return f"Vlan{number}"


def validate_site(value: Optional[str], allowed: List[str]) -> Optional[str]:
    if value is None or not str(value).strip():
        return None
    v = str(value).strip().lower()
    if v not in allowed:
        raise ValidationError(
            f"Location '{value}' is not recognised. Choose one of: "
            f"{', '.join(allowed)}."
        )
    return v


def validate_switch_type(value: Optional[str], allowed) -> str:
    v = (value or "ios").strip().lower()
    if v not in allowed:
        raise ValidationError(
            f"Switch type '{value}' is not supported. Choose IOS or Nexus."
        )
    return v


IDLE_TIMEOUT_MINUTES = (0, 1, 5, 10, 15, 20, 30, 60, 120)  # 0 = Never


def validate_idle_timeout_minutes(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError("Idle timeout must be a whole number of minutes.")
    if n not in IDLE_TIMEOUT_MINUTES:
        raise ValidationError(
            "Idle timeout must be one of: Never, 1, 5, 10, 15, 20, or 30 "
            "minutes, or 1 or 2 hours."
        )
    return n


LOG_DELETE_DAY_OPTIONS = (14, 30, 90, 180, 365)
LOG_AUTO_DELETE_DAY_OPTIONS = (0, 14, 30, 90, 180, 365)  # 0 = Never


def validate_log_delete_days(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError("Choose a valid retention period.")
    if n not in LOG_DELETE_DAY_OPTIONS:
        raise ValidationError("Choose one of the listed retention periods.")
    return n


def validate_log_auto_delete_days(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise ValidationError("Choose a valid retention period.")
    if n not in LOG_AUTO_DELETE_DAY_OPTIONS:
        raise ValidationError(
            "Auto-delete must be Never, 1 month, 3 months, 6 months, or 1 year."
        )
    return n


_TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
_DATE_RE = re.compile(r"^\d{1,2} [A-Z][a-z]{2} \d{4}$")

_DAYS = {"daily", "weekdays", "weekend", "monday", "tuesday", "wednesday",
         "thursday", "friday", "saturday", "sunday"}


def validate_time(value: str, field: str) -> str:
    v = check_cli_safe(value or "", field)
    if not _TIME_RE.match(v):
        raise ValidationError(f"{field} must be in HH:MM 24-hour format (e.g. 08:30).")
    return v


def validate_cisco_date(value: str, field: str) -> str:
    v = check_cli_safe(value or "", field)
    if not _DATE_RE.match(v):
        raise ValidationError(f"{field} must look like '1 Jan 2026'.")
    return v


def validate_days(value: str) -> str:
    v = check_cli_safe(value or "daily", "Days").lower()
    if v not in _DAYS:
        raise ValidationError(
            f"Day selection '{value}' is not valid."
        )
    return v


def validate_acl_rule_line(line: str) -> str:
    """Validate one manually edited permit/deny ACL rule line."""
    v = check_cli_safe(line or "", "Rule")
    if not v:
        raise ValidationError("The rule line is empty.")
    if len(v) > 400:
        raise ValidationError("The rule line is too long (max 400 characters).")
    body = re.sub(r"^\d+\s+", "", v).strip().lower()
    if not body.startswith(("permit ", "deny ")):
        raise ValidationError(
            "The rule must start with 'permit' or 'deny' (optionally preceded "
            "by a sequence number).")
    return v


def validate_permit_rule_line(line: str) -> str:
    """Validate an admin-edited permit rule before sending it to a switch."""
    v = validate_acl_rule_line(line)
    body = re.sub(r"^\d+\s+", "", v).strip().lower()
    if body.startswith("deny"):
        raise ValidationError(
            "Deny rules cannot be created from this application. "
            "Only permit rules are allowed."
        )
    return v
