"""
ACL parsing and evaluation engine.
Pure deterministic rule-based logic — no AI/ML.
"""
import re
import ipaddress
from datetime import datetime
from typing import Optional, Tuple, List, Dict, Any


# ---------------------------------------------------------------------------
# IP / Subnet helpers
# ---------------------------------------------------------------------------

def wildcard_to_prefix(wildcard: str) -> int:
    """Convert a Cisco wildcard mask to a prefix length."""
    parts = wildcard.split(".")
    inverted = [str(255 - int(p)) for p in parts]
    net = ipaddress.IPv4Network(f"0.0.0.0/{'.'.join(inverted)}", strict=False)
    return net.prefixlen


def prefix_to_wildcard(prefix: int) -> str:
    """Convert an IPv4 prefix length to a Cisco wildcard mask."""
    bits = (0xFFFFFFFF >> prefix) & 0xFFFFFFFF
    return ".".join([str((bits >> (8 * i)) & 0xFF)
                     for i in range(3, -1, -1)])


def ip_matches_rule_addr(test_ip_str: str, rule_ip: str, rule_mask: str) -> bool:
    """
    Check if test_ip_str (single host or subnet) falls within the network
    defined by rule_ip + wildcard mask (or 'host' keyword or 'any').
    test_ip_str may be a host (e.g. 1.2.3.4) or a subnet (e.g. 1.2.3.0/24).
    """
    if rule_ip == "any":
        return True

    try:
        test_net = ipaddress.IPv4Network(test_ip_str, strict=False)
    except ValueError:
        return False

    try:
        prefix = wildcard_to_prefix(rule_mask)
        rule_net = ipaddress.IPv4Network(f"{rule_ip}/{prefix}", strict=False)
    except ValueError:
        return False

    # test subnet must be fully contained within rule_net
    return test_net.subnet_of(rule_net)

def port_matches(test_port: Optional[int], rule_op: str, rule_ports: List[int]) -> bool:
    """
    Evaluate whether test_port satisfies the rule port condition.
    test_port=None means any port (matches portless checks).
    rule_op: '', 'eq', 'neq', 'lt', 'gt', 'range'
    """
    if not rule_op:
        return True  # no port restriction in rule
    if test_port is None:
        # user didn't specify port — only matches if rule has no port restriction
        return False
    if rule_op == "eq":
        return test_port in rule_ports
    if rule_op == "neq":
        return test_port not in rule_ports
    if rule_op == "lt":
        return test_port < rule_ports[0]
    if rule_op == "gt":
        return test_port > rule_ports[0]
    if rule_op == "range":
        return rule_ports[0] <= test_port <= rule_ports[1]
    return False


# Named port map (common services)
# Based on Cisco IOS/NX-OS named port definitions
NAMED_PORTS: Dict[str, int] = {
    # Common protocols
    "ftp-data": 20,
    "ftp": 21,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "domain": 53,
    "dns": 53,
    "tftp": 69,
    "http": 80,
    "www": 80,
    "pop3": 110,
    "ntp": 123,
    "netbios-ns": 137,
    "netbios-dgm": 138,
    "netbios-ssn": 139,
    "imap": 143,
    "snmp": 161,
    "snmptrap": 162,
    "bgp": 179,
    "ldap": 389,
    "https": 443,
    "syslog": 514,
    "kerberos": 88,
    "msrpc": 135,
    "radius": 1812,
    "sqlnet": 1521,
    "oracle": 1521,
    "rdp": 3389,
    "isakmp": 500,
    "bootps": 67,
    "bootpc": 68,
    "rip": 520,
    
    # Additional named ports from Cisco IOS/NX-OS
    "echo": 7,
    "discard": 9,
    "daytime": 13,
    "chargen": 19,
    "time": 37,
    "tacacs": 49,
    "whois": 43,
    "gopher": 70,
    "finger": 79,
    "hostname": 101,
    "pop2": 109,
    "sunrpc": 111,
    "ident": 113,
    "nntp": 119,
    "irc": 194,
    "pim-auto-rp": 496,
    "exec": 512,
    "login": 513,
    "cmd": 514,
    "lpd": 515,
    "talk": 517,
    "uucp": 540,
    "klogin": 543,
    "kshell": 544,
    "drip": 3949,
    "onep-plain": 15001,
    "onep-tls": 15002,
    "biff": 512,
    "dnsix": 195,
    "mobile-ip": 434,
    "nameserver": 42,
    "netbios-ss": 139,
    "non500-isakmp": 4500,
    "ripv6": 521,
    "who": 513,
    "xdmcp": 177,
}


# The Cisco ICMP message types this app exposes as a dropdown (there are more
# in the full IOS/NX-OS keyword set, but these are the ones that matter here).
# NOTE: this set gates the write-path dropdown only (validate_icmp_type). The
# *parser* below deliberately does not gate on this set — see
# _ICMP_OTHER_CLAUSE_KEYWORDS and the icmp_type parsing block, which must
# recognize any real ICMP type keyword (not just these 8) so two rules using
# two different types are never mistaken for having "no type" in common.
ICMP_TYPES = {
    "echo", "echo-reply", "unreachable", "administratively-prohibited",
    "packet-too-big", "time-exceeded", "redirect", "traceroute",
}

# Other keywords that can follow the two addresses in an ICMP ACL line
# (precedence/tos/fragments/log clauses, or time-range) — anything else in
# that position is the ICMP type itself, whether or not it's one of the 8
# above. Excluding these (and pure numbers, which would be an icmp-code)
# is what lets the parser recognize types outside the dropdown's 8 without
# maintaining an exhaustive list of every Cisco ICMP keyword.
_ICMP_OTHER_CLAUSE_KEYWORDS = {"time-range", "precedence", "tos", "fragments", "log"}


def resolve_port(token: str) -> int:
    """Resolve a named or numeric port to an integer."""
    if token.isdigit():
        return int(token)
    return NAMED_PORTS.get(token.lower(), 0)


# ---------------------------------------------------------------------------
# ACL rule parser
# ---------------------------------------------------------------------------

def parse_acl_rule(
    line: str,
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
) -> Optional[Dict[str, Any]]:
    """
    Parse a single ACL rule line into a structured dict.
    Returns None if the line is not a permit/deny rule.

    Parsing is platform-aware:
    - NX-OS uses ``addrgroup`` / ``portgroup`` and permits CIDR addresses.
    - IOS uses ``object-group`` for both kinds. A service object group appears
      in the protocol position, before both addresses, so header-derived group
      types are required to distinguish it from network object groups.

    ``acl_kind`` selects standard-ACL parsing (source address only, no
    protocol/ports) when set to ``"standard"``; any other value parses the
    normal extended-ACL shape.
    """
    line = line.strip()
    # Remove leading sequence number
    line = re.sub(r"^\d+\s+", "", line)

    raw_line = line
    # 'show ip access-lists' renders a standard-ACL wildcard as
    #   permit 172.30.2.192, wildcard bits 0.0.0.63
    # rather than the configured "<address> <wildcard>". Normalise it for
    # tokenising only, so the address operand parser sees the usual form
    # while `raw` still reports the line exactly as the switch printed it.
    line = re.sub(r",\s*wildcard bits\s+", " ", line, flags=re.IGNORECASE)

    m = re.match(r"^(permit|deny)\s+(.+)$", line, re.IGNORECASE)
    if not m:
        return None

    action = m.group(1).lower()
    rest = m.group(2).strip()
    tokens = rest.split()
    idx = 0
    platform = (switch_type or "ios").lower()
    is_nxos = platform in ("nexus", "nxos", "cisco_nxos")
    group_types = {name.lower(): kind for name, kind in
                   (object_group_types or {}).items()}

    class ParseError(Exception):
        pass

    def peek(offset=0):
        pos = idx + offset
        return tokens[pos] if pos < len(tokens) else None

    def consume():
        nonlocal idx
        if idx >= len(tokens):
            raise ParseError
        t = tokens[idx]
        idx += 1
        return t

    def group_kind(name: str) -> Optional[str]:
        return group_types.get(name.lower())

    def valid_port_token(token: Optional[str]) -> bool:
        if not token:
            return False
        if token.isdigit():
            return 0 <= int(token) <= 65535
        return token.lower() in NAMED_PORTS

    try:
        def parse_addr():
            """Parse one address according to the selected switch platform."""
            tok = peek()
            if tok is None:
                raise ParseError
            tok_lower = tok.lower()
            if tok_lower == "any":
                consume()
                return "any", "0.0.0.0", None
            if tok_lower == "host":
                consume()
                ip = consume()
                ipaddress.IPv4Address(ip)
                return ip, "0.0.0.0", None
            if is_nxos and tok_lower == "addrgroup":
                consume()
                name = consume()
                if group_types and group_kind(name) != "address":
                    raise ParseError
                return "addrgroup", None, name
            if not is_nxos and tok_lower == "object-group":
                consume()
                name = consume()
                if group_kind(name) != "address":
                    raise ParseError
                return "addrgroup", None, name

            literal = consume()
            if "/" in literal:
                if not is_nxos:
                    raise ParseError
                network = ipaddress.IPv4Network(literal, strict=False)
                return (str(network.network_address),
                        prefix_to_wildcard(network.prefixlen), None)

            ipaddress.IPv4Address(literal)
            wc = peek()
            if wc and re.fullmatch(r"\d+\.\d+\.\d+\.\d+", wc):
                octets = [int(x) for x in wc.split(".")]
                if all(0 <= octet <= 255 for octet in octets):
                    consume()
                    # Validate that the wildcard is contiguous.
                    wildcard_to_prefix(wc)
                    return literal, wc, None
            return literal, "0.0.0.0", None

        if (acl_kind or "extended").lower() == "standard":
            # Standard ACLs carry no protocol token and only a source address:
            #   permit|deny {source [wildcard] | any | host source}
            # Normalized into the same dict shape as an extended rule (proto
            # "ip", destination "any") so every downstream comparison function
            # needs no standard-ACL-specific handling at all.
            src_ip, src_wc, src_addrgroup = parse_addr()
            return {
                "action": action, "proto": "ip",
                "src_ip": src_ip, "src_wc": src_wc, "src_addrgroup": src_addrgroup,
                "src_port_op": "", "src_ports": [], "src_portgroup": None,
                "dst_ip": "any", "dst_wc": "0.0.0.0", "dst_addrgroup": None,
                "dst_port_op": "", "dst_ports": [], "dst_portgroup": None,
                "icmp_type": None, "service_group": None, "established": False,
                "time_range": None, "raw": raw_line,
            }

        # IOS service groups occupy the protocol position:
        #   permit object-group WEB_PORT <source> <destination>
        ios_service_group = None
        if (not is_nxos and peek() and peek().lower() == "object-group"):
            consume()
            candidate = consume()
            if group_kind(candidate) != "port":
                return None
            ios_service_group = candidate
            proto = "ip"  # member protocols are checked during evaluation
        else:
            proto = consume().lower()

        def parse_port_op():
            """Parse an optional port operator following an address."""
            tok = peek()
            if tok is None:
                return "", [], None
            tok_lower = tok.lower()
            if is_nxos and tok_lower == "portgroup":
                consume()
                name = consume()
                if group_types and group_kind(name) != "port":
                    raise ParseError
                return "portgroup", [], name
            if tok_lower in ("eq", "neq"):
                op = consume().lower()
                ports = []
                while valid_port_token(peek()):
                    ports.append(resolve_port(consume()))
                if not ports:
                    raise ParseError
                return op, ports, None
            if tok_lower in ("lt", "gt"):
                op = consume().lower()
                port_tok = consume()
                if not valid_port_token(port_tok):
                    raise ParseError
                return op, [resolve_port(port_tok)], None
            if tok_lower == "range":
                consume()
                first, second = consume(), consume()
                if not valid_port_token(first) or not valid_port_token(second):
                    raise ParseError
                return "range", [resolve_port(first), resolve_port(second)], None
            return "", [], None

        src_ip, src_wc, src_addrgroup = parse_addr()

        src_port_op, src_ports, src_portgroup = "", [], None
        if proto in ("tcp", "udp") and not ios_service_group:
            src_port_op, src_ports, src_portgroup = parse_port_op()

        dst_ip, dst_wc, dst_addrgroup = parse_addr()

        dst_port_op, dst_ports, dst_portgroup = "", [], None
        if proto in ("tcp", "udp") and not ios_service_group:
            dst_port_op, dst_ports, dst_portgroup = parse_port_op()

        icmp_type = None
        if proto == "icmp" and not ios_service_group:
            tok = peek()
            if (tok and not tok.isdigit()
                    and tok.lower() not in _ICMP_OTHER_CLAUSE_KEYWORDS):
                icmp_type = consume().lower()

        # 'established' (TCP only) matches segments carrying ACK/RST — return
        # traffic inside a session the other end opened — and never the
        # initial SYN. It follows both address/port operands and precedes any
        # time-range. Capturing it matters beyond round-tripping the text: it
        # makes the rule strictly NARROWER than the same rule without it, so
        # coverage/summary comparisons must be able to see it.
        established = False
        if peek() and peek().lower() == "established":
            consume()
            established = True

        time_range_name = None
        if peek() and peek().lower() == "time-range":
            consume()
            time_range_name = consume()
    except (ParseError, ValueError):
        return None

    return {
        "action": action,
        "proto": proto,
        "src_ip": src_ip,
        "src_wc": src_wc,
        "src_addrgroup": src_addrgroup,
        "src_port_op": src_port_op,
        "src_ports": src_ports,
        "src_portgroup": src_portgroup,
        "dst_ip": dst_ip,
        "dst_wc": dst_wc,
        "dst_addrgroup": dst_addrgroup,
        "dst_port_op": dst_port_op,
        "dst_ports": dst_ports,
        "dst_portgroup": dst_portgroup,
        "icmp_type": icmp_type,
        "service_group": ios_service_group,
        "established": established,
        "time_range": time_range_name,
        "raw": raw_line,
    }


# ---------------------------------------------------------------------------
# Route output parser
# ---------------------------------------------------------------------------

def parse_route_output(output: str) -> Dict[str, Any]:
    """
    Parse 'show ip route <ip>' output.
    Returns dict: {
        'on_switch': bool,
        'vlan': str or None,
        'interface': str or None,
    }
    
    Handles both IOS and NX-OS formats:
    - IOS: "directly connected, via Vlan10"
    - NX-OS: "*via 192.168.254.253, Vlan1258, [0/0], 6w3d, direct"
    
    Logic:
    - If route includes "Vlan*" and "direct" (or "directly connected") → on_switch=True
    - Otherwise → on_switch=False
    """
    # FIRST: Check for NX-OS format with VLAN and direct keyword
    # Pattern: via <ip>, Vlan<num>, ..., direct
    # Also matches routes without explicit "direct" keyword if they show attached format
    m = re.search(r"via\s+[\d.]+,\s+(Vlan\d+),.*\b(?:direct|am(?:sw)?)\b", output, re.IGNORECASE)
    if m:
        vlan = m.group(1)
        return {"on_switch": True, "vlan": vlan, "interface": vlan}
    
    # Check for NX-OS attached routes: via <same-ip-as-queried>, Vlan<num> (without direct keyword)
    # This handles cases where the route shows "via X.X.X.X, VlanY" where X.X.X.X is the interface IP itself
    m = re.search(r"\*?via\s+([\d.]+),\s+(Vlan\d+),\s*\[[^\]]+\]", output, re.IGNORECASE)
    if m:
        vlan = m.group(2)
        return {"on_switch": True, "vlan": vlan, "interface": vlan}

    # SECOND: Check for IOS format: directly connected via Vlan
    m = re.search(r"directly connected,\s*via\s+(Vlan\d+)", output, re.IGNORECASE)
    if m:
        vlan = m.group(1)
        return {"on_switch": True, "vlan": vlan, "interface": vlan}

    # THIRD: Check for IOS format: directly connected via any interface (not VLAN)
    m = re.search(r"directly connected,\s*via\s+(\S+)", output, re.IGNORECASE)
    if m:
        iface = m.group(1)
        return {"on_switch": False, "vlan": None, "interface": iface}

    # FOURTH: Check for NX-OS format: via next-hop IP (not direct)
    m = re.search(r"via\s+[\d.]+,\s*(\S+)", output, re.IGNORECASE)
    if m:
        return {"on_switch": False, "vlan": None, "interface": m.group(1)}

    # No match found
    return {"on_switch": False, "vlan": None, "interface": None}


def parse_interface_acl(output: str) -> List[Dict[str, str]]:
    """
    Parse 'show running-config interface VlanX' output.
    Returns list of {acl_name, direction} for all ip access-group lines.
    """
    results = []
    for line in output.splitlines():
        m = re.search(r"ip\s+access-group\s+(\S+)\s+(in|out)", line, re.IGNORECASE)
        if m:
            results.append({"acl_name": m.group(1), "direction": m.group(2).lower()})
    return results


def parse_acl_lines(output: str) -> List[str]:
    """
    Extract individual ACL rule lines from 'show ip access-lists <name>' output.
    Returns list of raw rule strings (stripped, with sequence numbers preserved).
    """
    rules = []
    for line in output.splitlines():
        line = line.strip()
        # Lines starting with a number followed by permit/deny
        if re.match(r"^\d+\s+(permit|deny)\s+", line, re.IGNORECASE):
            rules.append(line)
        # Lines starting directly with permit/deny (no sequence number)
        elif re.match(r"^(permit|deny)\s+", line, re.IGNORECASE):
            rules.append(line)
    return rules


def parse_acl_kinds(output: str) -> Dict[str, str]:
    """
    Map each ACL name to 'standard' or 'extended' from an unfiltered
    'show ip access-lists' dump. Use the unfiltered listing, not a
    name-filtered 'show ip access-lists <name>' query — some IOS platforms
    omit the Standard/Extended prefix once a specific name is given, even
    though the unfiltered listing always includes it. NX-OS has no such
    prefix at all (no standard/extended split) and defaults to 'extended',
    which _acl_ctx() already treats as a no-op for NX-OS.
    """
    kinds: Dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        header = re.match(r"^(Standard|Extended)?\s*IP access list\s+(\S+)",
                          line, re.IGNORECASE)
        if header:
            kinds[header.group(2)] = (header.group(1) or "extended").lower()
    return kinds


def parse_all_acl_rules(output: str) -> Dict[str, List[str]]:
    """
    Split an unfiltered 'show ip access-lists' dump (every ACL on the switch)
    into per-ACL rule lines, keyed by ACL name in the order they appear.
    Lets callers fetch every ACL's rules in a single command instead of one
    'show ip access-lists <name>' round trip per ACL.
    """
    result: Dict[str, List[str]] = {}
    current = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        header = re.match(r"^(?:Standard|Extended)?\s*IP access list\s+(\S+)",
                          line, re.IGNORECASE)
        if header:
            current = header.group(1)
            result.setdefault(current, [])
            continue
        if current is None:
            continue
        if (re.match(r"^\d+\s+(permit|deny)\s+", line, re.IGNORECASE) or
                re.match(r"^(permit|deny)\s+", line, re.IGNORECASE)):
            result[current].append(line)
    return result


def parse_time_range_active(output: str) -> bool:
    """
    Parse 'show time-range <name>' output.
    Returns True if the time-range is currently ACTIVE.
    """
    for line in output.splitlines():
        if re.search(r"\*\s*active\b", line, re.IGNORECASE):
            return True
    return False


def parse_object_group_addresses(output: str) -> List[str]:
    """
    Parse object-group network output.
    Returns list of IP/prefix strings, plus special 'range:start-end' format for ranges.
    
    Supports:
    - host 1.2.3.4
    - 1.2.3.4 (single IP, treated as /32)
    - 1.2.3.0 0.0.0.255 (wildcard mask)
    - 1.2.3.0 255.255.255.0 (subnet mask - converted to CIDR)
    - 1.2.3.0/24 (CIDR notation)
    - range 1.2.3.10 1.2.3.20
    - Handles both IOS and NX-OS formats
    - Skips object group headers and sequence numbers
    """
    addrs = []
    for line in output.splitlines():
        line = line.strip()
        
        # Skip empty lines, headers, and description/comment lines
        if not line:
            continue
        if line.lower().startswith(('description', '#', '!')):
            continue
        # Skip object group headers
        if re.match(r"^(IPv4\s+address\s+object-group|Protocol\s+port\s+object-group|Network\s+object\s+group|Service\s+object\s+group)", line, re.IGNORECASE):
            continue
        
        # Remove leading sequence numbers (e.g., "10 host 192.168.1.1")
        line = re.sub(r"^\d+\s+", "", line)
        
        # host 1.2.3.4
        m = re.match(r"^host\s+([\d.]+)$", line, re.IGNORECASE)
        if m:
            addrs.append(m.group(1) + "/32")
            continue
        
        # range 1.2.3.10 1.2.3.20
        m = re.match(r"^range\s+([\d.]+)\s+([\d.]+)$", line, re.IGNORECASE)
        if m:
            addrs.append(f"range:{m.group(1)}-{m.group(2)}")
            continue
        
        # 1.2.3.0/24 (CIDR notation) - check this before IP+mask to avoid confusion
        m = re.match(r"^([\d.]+/\d+)$", line)
        if m:
            try:
                net = ipaddress.IPv4Network(m.group(1), strict=False)
                addrs.append(str(net))
            except ValueError:
                pass
            continue
        
        # 1.2.3.0 0.0.0.255 (IP with wildcard mask) OR 1.2.3.0 255.255.255.0 (subnet mask)
        m = re.match(r"^([\d.]+)\s+([\d.]+)$", line)
        if m:
            ip_str = m.group(1)
            mask_str = m.group(2)
            try:
                # Try to determine if it's a wildcard mask or subnet mask
                # Wildcard masks typically start with 0 (e.g., 0.0.0.255)
                # Subnet masks typically start with 255 (e.g., 255.255.255.0)
                mask_octets = [int(x) for x in mask_str.split(".")]
                
                # If first octet is 0, likely a wildcard mask
                if mask_octets[0] == 0:
                    prefix = wildcard_to_prefix(mask_str)
                    net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
                    addrs.append(str(net))
                # If first octet is 255, likely a subnet mask
                elif mask_octets[0] == 255:
                    # Convert subnet mask to CIDR
                    net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                    addrs.append(str(net))
                else:
                    # Ambiguous - try wildcard first, then subnet mask
                    try:
                        prefix = wildcard_to_prefix(mask_str)
                        net = ipaddress.IPv4Network(f"{ip_str}/{prefix}", strict=False)
                        addrs.append(str(net))
                    except:
                        net = ipaddress.IPv4Network(f"{ip_str}/{mask_str}", strict=False)
                        addrs.append(str(net))
            except (ValueError, Exception):
                pass
            continue
        
        # Single IP address without mask (treat as /32)
        m = re.match(r"^([\d.]+)$", line)
        if m:
            try:
                ipaddress.IPv4Address(m.group(1))
                addrs.append(m.group(1) + "/32")
            except ValueError:
                pass
    
    return addrs


def parse_object_group_services(
    output: str,
) -> List[Tuple[Optional[str], Optional[str], str, List[int]]]:
    """
    Parse service/port object-group members.

    Returns ``(protocol, position, operator, ports)`` tuples. IOS service
    members carry ``tcp``, ``udp`` or ``tcp-udp`` and may explicitly say
    ``source`` or ``destination``. An omitted position means destination for
    IOS service groups; NX-OS port groups derive their position from the ACL.
    
    Handles:
    - eq 80, neq 22, lt 1024, gt 1024
    - range 8000 8100
    - Plain port numbers or names
    - Sequence numbers (e.g., "10 eq 80")
    - Protocol prefixes (e.g., "tcp eq 80", "udp range 1000 2000")
    - Both IOS and NX-OS formats
    """
    result: List[Tuple[Optional[str], Optional[str], str, List[int]]] = []
    for line in output.splitlines():
        line = line.strip()
        
        # Skip empty lines and headers
        if not line:
            continue
        if line.lower().startswith(('description', '#', '!')):
            continue
        # Skip object group headers
        if re.match(r"^(IPv4\s+address\s+object-group|Protocol\s+port\s+object-group|Network\s+object\s+group|Service\s+object\s+group|object-group)", line, re.IGNORECASE):
            continue
        
        # Remove leading sequence numbers (e.g., "10 eq 80" -> "eq 80")
        line = re.sub(r"^\d+\s+", "", line)
        
        protocol = None
        if re.fullmatch(r"tcp|udp|tcp-udp", line, re.IGNORECASE):
            result.append((line.lower(), None, "", []))
            continue
        m = re.match(r"^(tcp|udp|tcp-udp)\s+(.+)$", line, re.IGNORECASE)
        if m:
            protocol = m.group(1).lower()
            line = m.group(2)

        position = None
        m = re.match(r"^(source|destination)\s+(.+)$", line, re.IGNORECASE)
        if m:
            position = m.group(1).lower()
            line = m.group(2)
        
        # eq|neq|lt|gt port — object-group service members take exactly one
        # port each (unlike a plain ACL rule line's eq/neq, which can list
        # several ports).
        m = re.match(r"^(eq|neq|lt|gt)\s+(\S+)$", line, re.IGNORECASE)
        if m:
            result.append((protocol, position, m.group(1).lower(),
                           [resolve_port(m.group(2))]))
            continue
        
        # range start end
        m = re.match(r"^range\s+(\S+)\s+(\S+)$", line, re.IGNORECASE)
        if m:
            result.append((protocol, position, "range",
                           [resolve_port(m.group(1)), resolve_port(m.group(2))]))
            continue
        
        # plain port number or name (treat as eq)
        m = re.match(r"^(\S+)$", line)
        if m and (m.group(1).isdigit() or m.group(1).lower() in NAMED_PORTS):
            result.append((protocol, position, "eq", [resolve_port(m.group(1))]))
    
    return result


def parse_object_group_ports(output: str) -> List[Tuple[str, List[int]]]:
    """Backward-compatible port conditions without member protocols."""
    return [(op, ports) for _protocol, _position, op, ports
            in parse_object_group_services(output)]


# ---------------------------------------------------------------------------
# Rule matching engine
# ---------------------------------------------------------------------------

def proto_matches(user_proto: str, rule_proto: str) -> bool:
    """
    Check if user's requested protocol matches the rule's protocol.
    user_proto: 'tcp', 'udp', 'icmp', 'all'
    rule_proto: 'ip', 'tcp', 'udp', 'icmp', etc.
    """
    user_proto = user_proto.lower()
    rule_proto = rule_proto.lower()
    if rule_proto == "ip":
        return True  # ip matches everything
    if user_proto == "all":
        return False  # a protocol-specific rule cannot cover all IP traffic
    return user_proto == rule_proto


def icmp_type_matches(user_type: Optional[str], rule_type: Optional[str]) -> bool:
    """
    Check if a user's ICMP type query satisfies a rule's ICMP type condition.
    Mirrors port_matches: no restriction on the rule matches any query
    (including an unspecified one); a type-restricted rule only matches an
    equally specific, equal query.
    """
    if not rule_type:
        return True
    if not user_type:
        return False
    return user_type.lower() == rule_type.lower()


def icmp_type_covers(a_type: Optional[str], b_type: Optional[str]) -> bool:
    """
    Return True if a_type's ICMP-type restriction covers b_type's.
    No type on the broader rule covers every type (including no type); two
    different specific types never cover each other.
    """
    if not a_type:
        return True
    return bool(b_type) and a_type.lower() == b_type.lower()


def evaluate_rule(
    rule: Dict[str, Any],
    user_src: str,
    user_dst: str,
    user_proto: str,
    user_port: Optional[int],
    acl_direction: str,  # 'in' or 'out'
    vlan_ip_side: str,   # 'src' or 'dst' — which side is the VLAN interface
    addrgroup_ips: Dict[str, List[str]],
    portgroup_ports: Dict[str, List[Tuple]],
    user_icmp_type: Optional[str] = None,
) -> Optional[str]:
    """
    Evaluate a single parsed rule against the user's query.

    Returns 'permit', 'deny', or None (no match).

    DIRECTIONAL LOGIC:
    - ACL 'in' on VLAN X: rule's FIRST IP position = VLAN X side
    - ACL 'out' on VLAN X: rule's SECOND IP position = VLAN X side

    BIDIRECTIONAL vs ONE-WAY:
    - If no port in rule: bidirectional match (source/dest can be in any order)
    - If port in rule: one-way — the IP with the port qualifier is the destination
    """
    if not proto_matches(user_proto, rule["proto"]):
        return None

    if (rule["proto"].lower() == "icmp" and
            not icmp_type_matches(user_icmp_type, rule.get("icmp_type"))):
        return None

    has_port_in_rule = bool(rule["src_port_op"] or rule["dst_port_op"] or
                            rule["src_portgroup"] or rule["dst_portgroup"] or
                            rule.get("service_group"))

    # Resolve address groups
    def get_ips(ip, wc, addrgroup):
        if addrgroup:
            if addrgroup in addrgroup_ips:
                return addrgroup_ips[addrgroup]
            return next((members for name, members in addrgroup_ips.items()
                         if name.lower() == addrgroup.lower()), [])
        if ip == "any":
            return ["any"]
        return [(ip + "/" + str(wildcard_to_prefix(wc))) if wc != "0.0.0.0"
                else (ip + "/32")]

    rule_first_ips = get_ips(rule["src_ip"], rule["src_wc"], rule["src_addrgroup"])
    rule_second_ips = get_ips(rule["dst_ip"], rule["dst_wc"], rule["dst_addrgroup"])

    def ip_in_list(test_ip: str, ip_list: List[str]) -> bool:
        """Check if test_ip matches any entry in ip_list.
        
        Handles:
        - "any" keyword
        - Network prefixes (e.g., "192.168.1.0/24")
        - IP ranges (e.g., "range:192.168.1.10-192.168.1.20")
        """
        if "any" in ip_list:
            return True
        
        # Parse test_ip to get the actual IP address (remove /32 if present)
        try:
            test_ip_obj = ipaddress.IPv4Address(test_ip.split("/")[0])
        except (ValueError, ipaddress.AddressValueError):
            return False
        
        for entry in ip_list:
            if entry == "any":
                return True
            
            # Handle range format: "range:start-end"
            if entry.startswith("range:"):
                try:
                    range_part = entry.split(":", 1)[1]
                    start_ip, end_ip = range_part.split("-")
                    start_ip_obj = ipaddress.IPv4Address(start_ip.strip())
                    end_ip_obj = ipaddress.IPv4Address(end_ip.strip())
                    if start_ip_obj <= test_ip_obj <= end_ip_obj:
                        return True
                except (ValueError, ipaddress.AddressValueError, IndexError):
                    pass
                continue
            
            # Handle network prefix format: "192.168.1.0/24"
            try:
                if "/" in entry:
                    # Convert entry network to wildcard and use existing logic
                    if ip_matches_rule_addr(test_ip, entry.split("/")[0],
                                            prefix_to_wildcard(int(entry.split("/")[1]))):
                        return True
            except (ValueError, IndexError):
                pass
        
        return False

    def prefix_to_wildcard(prefix: int) -> str:
        bits = (0xFFFFFFFF >> prefix) & 0xFFFFFFFF
        return ".".join([str((bits >> (8 * i)) & 0xFF) for i in range(3, -1, -1)])

    # Resolve port groups
    def get_port_conditions(op, ports, portgroup_name):
        if portgroup_name:
            if portgroup_name in portgroup_ports:
                return portgroup_ports[portgroup_name]
            return next((conditions for name, conditions in portgroup_ports.items()
                         if name.lower() == portgroup_name.lower()), [])
        if op:
            return [(op, ports)]
        return []

    src_port_conds = get_port_conditions(rule["src_port_op"], rule["src_ports"], rule["src_portgroup"])
    dst_port_conds = get_port_conditions(rule["dst_port_op"], rule["dst_ports"], rule["dst_portgroup"])

    def port_satisfies(test_port, conditions):
        if not conditions:
            return True  # no port restriction
        for condition in conditions:
            if len(condition) == 4:
                member_proto, _position, op, ports = condition
            elif len(condition) == 3:
                member_proto, op, ports = condition
            else:
                member_proto, (op, ports) = None, condition
            if member_proto:
                allowed = ("tcp", "udp") if member_proto == "tcp-udp" else (member_proto,)
                # A protocol-specific service member can cover that protocol,
                # but it can never cover a request for all IP protocols.
                if user_proto == "all" or user_proto.lower() not in allowed:
                    continue
            if port_matches(test_port, op, ports):
                return True
        return False

    # An IOS service group precedes both addresses. Its member itself says
    # whether the port belongs to the source or destination; when omitted,
    # Cisco IOS treats it as the destination service.
    if rule.get("service_group"):
        service_conditions = get_port_conditions(
            "", [], rule["service_group"])
        for condition in service_conditions:
            if len(condition) == 4:
                member_proto, position, op, ports = condition
            elif len(condition) == 3:
                member_proto, op, ports = condition
                position = None
            else:
                member_proto, (op, ports) = None, condition
                position = None
            if member_proto:
                allowed = (("tcp", "udp") if member_proto == "tcp-udp"
                           else (member_proto,))
                if user_proto == "all" or user_proto.lower() not in allowed:
                    continue
            if not port_matches(user_port, op, ports):
                continue
            if position == "source":
                if (ip_in_list(user_src, rule_second_ips) and
                        ip_in_list(user_dst, rule_first_ips)):
                    return rule["action"]
            else:
                if (ip_in_list(user_src, rule_first_ips) and
                        ip_in_list(user_dst, rule_second_ips)):
                    return rule["action"]
        return None

    if not has_port_in_rule:
        # --- BIDIRECTIONAL: match in either order ---
        match_a = ip_in_list(user_src, rule_first_ips) and ip_in_list(user_dst, rule_second_ips)
        match_b = ip_in_list(user_dst, rule_first_ips) and ip_in_list(user_src, rule_second_ips)
        if match_a or match_b:
            return rule["action"]
        return None
    else:
        # --- ONE-WAY port logic ---
        #
        # The IP that has a port qualifier IMMEDIATELY after it in the rule syntax
        # is the DESTINATION of that port.  The other IP is the source.
        #
        # Case A: dst_port_op is set  →  rule_second (dst_ip) is the port destination
        #   Traffic direction: rule_first → rule_second:port
        #   Match only if: user_src matches rule_first AND user_dst matches rule_second AND user_port matches dst_port
        #
        # Case B: src_port_op is set  →  rule_first (src_ip) is the port destination
        #   Traffic direction: rule_second → rule_first:port
        #   Match only if: user_src matches rule_second AND user_dst matches rule_first AND user_port matches src_port
        #
        # Never allow the reverse direction for a port-qualified rule.

        if dst_port_conds:
            # Port destination is rule_second (dst position)
            # Allowed direction: rule_first → rule_second:port
            if (ip_in_list(user_src, rule_first_ips) and
                    ip_in_list(user_dst, rule_second_ips) and
                    port_satisfies(user_port, dst_port_conds)):
                return rule["action"]

        if src_port_conds:
            # Port destination is rule_first (src position)
            # Allowed direction: rule_second → rule_first:port
            if (ip_in_list(user_src, rule_second_ips) and
                    ip_in_list(user_dst, rule_first_ips) and
                    port_satisfies(user_port, src_port_conds)):
                return rule["action"]

        return None


# ---------------------------------------------------------------------------
# Redundancy checker
# ---------------------------------------------------------------------------

def _sequence_of(raw: str) -> Optional[int]:
    """Extract a rule line's leading sequence number, if any."""
    m = re.match(r"^\s*(\d+)\s", raw or "")
    return int(m.group(1)) if m else None


def check_redundant_rules(
    rules: List[str],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
    address_groups: Optional[Dict[str, List[str]]] = None,
    service_groups: Optional[Dict[str, List[Tuple]]] = None,
) -> List[Dict[str, Any]]:
    """
    Identify rules that are fully covered by an earlier (broader or identical)
    rule in the same ACL. Two coverage checks are tried for each pair: a plain
    structural comparison, and (when address_groups/service_groups are
    supplied) a group-aware one that resolves each side's object-group
    members into actual IP/port ranges — so a rule referencing one group can
    be found to cover a rule referencing a *different* group whose members
    are a subset, not just an identical group name.

    Returns one entry per covering rule, each listing every rule it covers
    (rather than one entry per redundant rule), so results already come
    pre-grouped for display:
      {"covered_by_rule": str, "covered_by_sequence": int|None,
       "redundant_rules": [{"raw": str, "sequence": int|None}, ...]}
    """
    address_groups = address_groups or {}
    service_groups = service_groups or {}
    # parse_acl_rule strips the leading sequence number before parsing, so
    # capture it from the original line here, before that happens.
    parsed = []
    seqs: List[Optional[int]] = []
    for raw in rules:
        p = parse_acl_rule(raw, switch_type, object_group_types, acl_kind)
        if p:
            parsed.append(p)
            seqs.append(_sequence_of(raw))

    groups: Dict[int, Dict[str, Any]] = {}
    order: List[int] = []
    for i, rule_b in enumerate(parsed):
        for j in range(i):
            rule_a = parsed[j]
            covers = (_rule_covers(rule_a, rule_b) or
                     rule_covers_with_group_members(
                         rule_a, rule_b, address_groups, service_groups))
            if covers:
                if j not in groups:
                    groups[j] = {
                        "covered_by_rule": rule_a["raw"],
                        "covered_by_sequence": seqs[j],
                        "redundant_rules": [],
                    }
                    order.append(j)
                groups[j]["redundant_rules"].append({
                    "raw": rule_b["raw"],
                    "sequence": seqs[i],
                })
                break
    return [groups[j] for j in order]


def rule_covers(rule_a: Dict, rule_b: Dict,
                require_same_action: bool = True) -> bool:
    """Return True if rule_a fully covers rule_b (rule_b is redundant)."""
    if require_same_action and rule_a["action"] != rule_b["action"]:
        return False
    a_time_range = (rule_a.get("time_range") or "").lower()
    b_time_range = (rule_b.get("time_range") or "").lower()
    if (a_time_range and a_time_range != b_time_range
            and (require_same_action or rule_a.get("action") != "deny")):
        return False
    if rule_a["proto"] != rule_b["proto"] and rule_a["proto"] != "ip":
        return False
    if (rule_a["proto"] == "icmp" and
            not icmp_type_covers(rule_a.get("icmp_type"), rule_b.get("icmp_type"))):
        return False
    # An 'established' rule only matches ACK/RST segments, so it is strictly
    # narrower and can never cover a rule without it — that rule also admits
    # the initial SYN. Treating them as equivalent would let the Redundancy
    # Checker recommend deleting the rule that actually permits connection
    # setup. The reverse direction is fine: no-established covers established.
    if rule_a.get("established") and not rule_b.get("established"):
        return False

    def addr_covers(a_ip, a_wc, a_group, b_ip, b_wc, b_group):
        if a_group or b_group:
            if a_ip == "any" and not a_group:
                return True
            return bool(a_group and b_group and
                        a_group.lower() == b_group.lower())
        if a_ip == "any":
            return True
        if b_ip == "any":
            return False
        try:
            a_prefix = wildcard_to_prefix(a_wc) if a_wc else 32
            b_prefix = wildcard_to_prefix(b_wc) if b_wc else 32
            a_net = ipaddress.IPv4Network(f"{a_ip}/{a_prefix}", strict=False)
            b_net = ipaddress.IPv4Network(f"{b_ip}/{b_prefix}", strict=False)
            return b_net.subnet_of(a_net)
        except Exception:
            return False

    src_ok = addr_covers(
        rule_a["src_ip"], rule_a["src_wc"], rule_a["src_addrgroup"],
        rule_b["src_ip"], rule_b["src_wc"], rule_b["src_addrgroup"])
    dst_ok = addr_covers(
        rule_a["dst_ip"], rule_a["dst_wc"], rule_a["dst_addrgroup"],
        rule_b["dst_ip"], rule_b["dst_wc"], rule_b["dst_addrgroup"])

    def port_covers(a_op, a_ports, a_group, b_op, b_ports, b_group):
        if a_group or b_group:
            if not a_op and not a_group:
                return True
            return bool(a_group and b_group and
                        a_group.lower() == b_group.lower())
        return _port_covers(a_op, a_ports, b_op, b_ports)

    if rule_a.get("service_group") or rule_b.get("service_group"):
        a_service = rule_a.get("service_group")
        b_service = rule_b.get("service_group")
        service_ok = (not a_service and rule_a["proto"] == "ip") or bool(
            a_service and b_service and a_service.lower() == b_service.lower())
        if not service_ok:
            return False

    src_port_ok = port_covers(
        rule_a["src_port_op"], rule_a["src_ports"],
        rule_a.get("src_portgroup"), rule_b["src_port_op"],
        rule_b["src_ports"], rule_b.get("src_portgroup"))
    dst_port_ok = port_covers(
        rule_a["dst_port_op"], rule_a["dst_ports"],
        rule_a.get("dst_portgroup"), rule_b["dst_port_op"],
        rule_b["dst_ports"], rule_b.get("dst_portgroup"))

    return src_ok and dst_ok and src_port_ok and dst_port_ok


def _rule_covers(rule_a: Dict, rule_b: Dict) -> bool:
    """Backward-compatible internal alias used by redundancy analysis."""
    return rule_covers(rule_a, rule_b)


def rule_covers_with_group_members(
        rule_a: Dict, rule_b: Dict,
        address_groups: Dict[str, List[str]],
        service_groups: Dict[str, List[Tuple]],
        require_same_action: bool = True) -> bool:
    """Coverage comparison with selective object-group member resolution."""
    if require_same_action and rule_a["action"] != rule_b["action"]:
        return False
    a_time_range = (rule_a.get("time_range") or "").lower()
    b_time_range = (rule_b.get("time_range") or "").lower()
    if (a_time_range and a_time_range != b_time_range
            and (require_same_action or rule_a.get("action") != "deny")):
        return False
    if (rule_a["proto"] == "icmp" and
            not icmp_type_covers(rule_a.get("icmp_type"), rule_b.get("icmp_type"))):
        return False
    # See rule_covers(): 'established' makes rule_a strictly narrower.
    if rule_a.get("established") and not rule_b.get("established"):
        return False

    def lookup(mapping, name):
        if not name:
            return None
        if name in mapping:
            return mapping[name]
        return next((value for key, value in mapping.items()
                     if key.lower() == name.lower()), None)

    def interval(spec):
        if spec == "any":
            return 0, 0xFFFFFFFF
        if spec.startswith("range:"):
            start, end = spec.split(":", 1)[1].split("-", 1)
            return int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
        network = ipaddress.IPv4Network(spec, strict=False)
        return int(network.network_address), int(network.broadcast_address)

    def address_specs(rule, position):
        group = rule[f"{position}_addrgroup"]
        if group:
            return lookup(address_groups, group) or []
        ip = rule[f"{position}_ip"]
        if ip == "any":
            return ["any"]
        wc = rule[f"{position}_wc"] or "0.0.0.0"
        prefix = wildcard_to_prefix(wc)
        return [str(ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False))]

    def addresses_cover(position):
        broader = [interval(spec) for spec in address_specs(rule_a, position)]
        narrower = [interval(spec) for spec in address_specs(rule_b, position)]
        return bool(broader and narrower) and all(
            any(a_start <= b_start and a_end >= b_end
                for a_start, a_end in broader)
            for b_start, b_end in narrower)

    def clauses(rule):
        service = rule.get("service_group")
        if service:
            members = lookup(service_groups, service) or []
            result = []
            for member_proto, member_position, op, ports in members:
                protocols = (("tcp", "udp") if member_proto == "tcp-udp"
                             else (member_proto,) if member_proto
                             else ("tcp", "udp"))
                position = member_position or "destination"
                position = "src" if position == "source" else "dst"
                for protocol in protocols:
                    result.append((protocol, position, op, ports))
            return result

        protocol = rule["proto"]
        result = []
        for position in ("src", "dst"):
            op = rule[f"{position}_port_op"]
            ports = rule[f"{position}_ports"]
            group = rule.get(f"{position}_portgroup")
            if group:
                members = lookup(service_groups, group) or []
                for member_proto, _member_position, member_op, member_ports in members:
                    protocols = (("tcp", "udp") if member_proto == "tcp-udp"
                                 else (member_proto,) if member_proto
                                 else (protocol,))
                    for member_protocol in protocols:
                        result.append((member_protocol, position, member_op,
                                       member_ports))
            elif op:
                result.append((protocol, position, op, ports))
        return result or [(protocol, None, "", [])]

    def clause_covers(a, b):
        a_proto, a_position, a_op, a_ports = a
        b_proto, b_position, b_op, b_ports = b
        if a_proto != "ip" and a_proto != b_proto:
            return False
        if a_position is not None and a_position != b_position:
            return False
        return _port_covers(a_op, a_ports, b_op, b_ports)

    # Service/protocol compatibility is checked before address groups are
    # resolved, avoiding unnecessary address expansion for unrelated rules.
    a_clauses = clauses(rule_a)
    b_clauses = clauses(rule_b)
    if not a_clauses or not b_clauses or not all(
            any(clause_covers(a, b) for a in a_clauses)
            for b in b_clauses):
        return False

    return addresses_cover("src") and addresses_cover("dst")


def _port_covers(a_op, a_ports, b_op, b_ports) -> bool:
    def intervals(op, ports):
        if not op:
            return [(0, 65535)]
        if op == "eq":
            return [(port, port) for port in sorted(set(ports))]
        if op == "range":
            return [(ports[0], ports[1])]
        if op == "lt":
            return [(0, ports[0] - 1)] if ports[0] > 0 else []
        if op == "gt":
            return [(ports[0] + 1, 65535)] if ports[0] < 65535 else []
        if op == "neq":
            excluded = sorted(set(ports))
            result, start = [], 0
            for port in excluded:
                if start <= port - 1:
                    result.append((start, port - 1))
                start = port + 1
            if start <= 65535:
                result.append((start, 65535))
            return result
        return []

    broader = intervals(a_op, a_ports)
    narrower = intervals(b_op, b_ports)
    return all(any(a_start <= b_start and a_end >= b_end
                   for a_start, a_end in broader)
               for b_start, b_end in narrower)


# ---------------------------------------------------------------------------
# Traffic overlap (distinct from "covers" — partial intersection, not full
# containment). Deliberately self-contained rather than sharing code with
# rule_covers_with_group_members/_port_covers above: this powers a
# security-sensitive check (see find_trailing_redundant_rules below), and
# keeping it isolated means a bug here can never come from — or leak into —
# the already-tested coverage logic.
# ---------------------------------------------------------------------------

def _port_range_list(op: str, ports: List[int]) -> List[Tuple[int, int]]:
    """Port operator -> list of (lo, hi) integer intervals."""
    if not op:
        return [(0, 65535)]
    if op == "eq":
        return [(port, port) for port in sorted(set(ports))]
    if op == "range":
        return [(ports[0], ports[1])]
    if op == "lt":
        return [(0, ports[0] - 1)] if ports[0] > 0 else []
    if op == "gt":
        return [(ports[0] + 1, 65535)] if ports[0] < 65535 else []
    if op == "neq":
        excluded = sorted(set(ports))
        result, start = [], 0
        for port in excluded:
            if start <= port - 1:
                result.append((start, port - 1))
            start = port + 1
        if start <= 65535:
            result.append((start, 65535))
        return result
    return []


def _addr_range_list(rule: Dict, position: str,
                     address_groups: Dict[str, List[str]]) -> List[Tuple[int, int]]:
    """A rule's src/dst address (literal or object-group) -> integer IP intervals."""
    def spec_interval(spec: str) -> Tuple[int, int]:
        if spec == "any":
            return 0, 0xFFFFFFFF
        if spec.startswith("range:"):
            start, end = spec.split(":", 1)[1].split("-", 1)
            return int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
        network = ipaddress.IPv4Network(spec, strict=False)
        return int(network.network_address), int(network.broadcast_address)

    group = rule.get(f"{position}_addrgroup")
    if group:
        members = address_groups.get(group)
        if members is None:
            members = next((v for k, v in address_groups.items()
                            if k.lower() == group.lower()), [])
        return [spec_interval(m) for m in members]
    ip = rule[f"{position}_ip"]
    if ip == "any":
        return [(0, 0xFFFFFFFF)]
    wc = rule[f"{position}_wc"] or "0.0.0.0"
    prefix = wildcard_to_prefix(wc)
    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
    return [(int(network.network_address), int(network.broadcast_address))]


def _service_clauses(rule: Dict,
                     service_groups: Dict[str, List[Tuple]]) -> List[Tuple]:
    """A rule's protocol/port (literal or object-group) -> (protocol, position,
    op, ports) tuples, resolving IOS service-group-as-protocol and port-group
    references to their real members."""
    def lookup(name):
        if not name:
            return None
        if name in service_groups:
            return service_groups[name]
        return next((v for k, v in service_groups.items()
                    if k.lower() == name.lower()), None)

    service = rule.get("service_group")
    if service:
        members = lookup(service) or []
        result = []
        for member_proto, member_position, op, ports in members:
            protocols = (("tcp", "udp") if member_proto == "tcp-udp"
                        else (member_proto,) if member_proto else ("tcp", "udp"))
            position = member_position or "destination"
            position = "src" if position == "source" else "dst"
            for protocol in protocols:
                result.append((protocol, position, op, ports))
        return result

    protocol = rule["proto"]
    result = []
    for position in ("src", "dst"):
        op = rule[f"{position}_port_op"]
        ports = rule[f"{position}_ports"]
        group = rule.get(f"{position}_portgroup")
        if group:
            members = lookup(group) or []
            for member_proto, _member_position, member_op, member_ports in members:
                protocols = (("tcp", "udp") if member_proto == "tcp-udp"
                            else (member_proto,) if member_proto else (protocol,))
                for member_protocol in protocols:
                    result.append((member_protocol, position, member_op, member_ports))
        elif op:
            result.append((protocol, position, op, ports))
    return result or [(protocol, None, "", [])]


def _ranges_overlap(a_list: List[Tuple[int, int]], b_list: List[Tuple[int, int]]) -> bool:
    return any(a0 <= b1 and b0 <= a1 for a0, a1 in a_list for b0, b1 in b_list)


def rules_traffic_overlaps(rule_a: Dict, rule_b: Dict,
                           address_groups: Optional[Dict[str, List[str]]] = None,
                           service_groups: Optional[Dict[str, List[Tuple]]] = None) -> bool:
    """
    Return True if rule_a and rule_b could both match at least one real
    packet — their protocol/address/port/ICMP-type scopes intersect.
    Order- and action-agnostic (unlike rule_covers, which requires full
    containment in one direction). Used to detect whether a rule sitting
    between a candidate redundant rule and a later, broader same-action rule
    could change the outcome for any of the overlapping traffic.
    """
    address_groups = address_groups or {}
    service_groups = service_groups or {}

    if (rule_a["proto"] != rule_b["proto"]
            and rule_a["proto"] != "ip" and rule_b["proto"] != "ip"):
        return False
    if rule_a["proto"] == "icmp" and rule_b["proto"] == "icmp":
        a_type, b_type = rule_a.get("icmp_type"), rule_b.get("icmp_type")
        if a_type and b_type and a_type.lower() != b_type.lower():
            return False

    def clause_overlaps(a, b):
        a_proto, a_position, a_op, a_ports = a
        b_proto, b_position, b_op, b_ports = b
        if a_proto != b_proto and a_proto != "ip" and b_proto != "ip":
            return False
        if a_position is not None and b_position is not None and a_position != b_position:
            return False
        return _ranges_overlap(_port_range_list(a_op, a_ports),
                               _port_range_list(b_op, b_ports))

    a_clauses = _service_clauses(rule_a, service_groups)
    b_clauses = _service_clauses(rule_b, service_groups)
    if not any(clause_overlaps(a, b) for a in a_clauses for b in b_clauses):
        return False

    return (_ranges_overlap(_addr_range_list(rule_a, "src", address_groups),
                            _addr_range_list(rule_b, "src", address_groups)) and
           _ranges_overlap(_addr_range_list(rule_a, "dst", address_groups),
                           _addr_range_list(rule_b, "dst", address_groups)))


def find_trailing_redundant_rules(
    rules: List[str],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
    address_groups: Optional[Dict[str, List[str]]] = None,
    service_groups: Optional[Dict[str, List[Tuple]]] = None,
) -> List[Dict[str, Any]]:
    """
    Identify rules that are only redundant because a LATER, broader rule with
    the same action covers them — safe only when no differently-acting rule
    strictly between the two has traffic that overlaps the candidate rule's
    (which would mean the candidate rule's presence still matters for that
    overlap). This is a separate, stricter-to-reason-about check from
    check_redundant_rules() (which only ever looks at earlier-covers-later);
    kept as an independent function/parse pass so that function's already-
    verified behavior can never be affected by this one.

    Returns the same grouped-by-covering-rule shape as check_redundant_rules().
    """
    address_groups = address_groups or {}
    service_groups = service_groups or {}
    parsed = []
    seqs: List[Optional[int]] = []
    for raw in rules:
        p = parse_acl_rule(raw, switch_type, object_group_types, acl_kind)
        if p:
            parsed.append(p)
            seqs.append(_sequence_of(raw))

    groups: Dict[int, Dict[str, Any]] = {}
    order: List[int] = []
    for i, rule_i in enumerate(parsed):
        for k in range(i + 1, len(parsed)):
            rule_k = parsed[k]
            if rule_k["action"] != rule_i["action"]:
                if rules_traffic_overlaps(rule_i, rule_k, address_groups, service_groups):
                    break  # a conflicting rule sits in between — not safe
                continue
            if (_rule_covers(rule_k, rule_i) or
                    rule_covers_with_group_members(
                        rule_k, rule_i, address_groups, service_groups)):
                if k not in groups:
                    groups[k] = {
                        "covered_by_rule": rule_k["raw"],
                        "covered_by_sequence": seqs[k],
                        "redundant_rules": [],
                    }
                    order.append(k)
                groups[k]["redundant_rules"].append({
                    "raw": rule_i["raw"],
                    "sequence": seqs[i],
                })
                break
    return [groups[k] for k in order]


def parse_vlan_acl_bindings_and_subnets(
    output: str,
) -> Tuple[Dict[str, List[Dict[str, str]]], Dict[str, str]]:
    """
    Single pass over 'show running-config' text, scoped to Vlan/SVI
    interfaces only (the wrong-direction check below only ever means
    something for VLAN interfaces, not physical/port-channel ones).

    Returns (acl_bindings, subnets):
      acl_bindings: {acl_name: [{"interface", "direction"}, ...]}
      subnets: {interface: "A.B.C.D/NN"} (each VLAN's own primary subnet)
    """
    acl_bindings: Dict[str, List[Dict[str, str]]] = {}
    subnets: Dict[str, str] = {}
    current_iface: Optional[str] = None
    is_vlan = False

    for raw in output.splitlines():
        m = re.match(r"^interface\s+(\S+)", raw, re.IGNORECASE)
        if m:
            current_iface = m.group(1)
            is_vlan = bool(re.match(r"^vlan\d+$", current_iface, re.IGNORECASE))
            continue
        if not is_vlan or not current_iface:
            continue

        m = re.search(r"\bip\s+access-group\s+(\S+)\s+(in|out)\b", raw, re.IGNORECASE)
        if m:
            acl_bindings.setdefault(m.group(1), []).append(
                {"interface": current_iface, "direction": m.group(2).lower()})
            continue

        if "secondary" in raw.lower() or current_iface in subnets:
            continue
        m = re.search(r"\bip\s+address\s+(\d+\.\d+\.\d+\.\d+)(?:/(\d+)|\s+(\d+\.\d+\.\d+\.\d+))",
                      raw, re.IGNORECASE)
        if m:
            try:
                if m.group(2):
                    prefix = int(m.group(2))
                else:
                    prefix = ipaddress.IPv4Network(f"0.0.0.0/{m.group(3)}", strict=False).prefixlen
                net = ipaddress.IPv4Network(f"{m.group(1)}/{prefix}", strict=False)
                subnets[current_iface] = str(net)
            except Exception:
                pass

    return acl_bindings, subnets



def find_dead_schedule_rules(
    rules: List[str],
    time_ranges: List[Dict[str, Any]],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    now: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Rules pinned to a time-range that can never fire again.

    Distinct from redundancy, and reported separately for a reason: a
    redundant rule is one another rule already covers, so removing it changes
    nothing. A dead-schedule rule matches nothing at all, and never will --
    the access it once described is already gone. The fix is usually to renew
    the schedule rather than to delete the rule, which is why this is a
    finding of its own rather than a third kind of redundancy.

    Expiry is decided by time_range_is_expired, so a `periodic weekdays` range
    that is merely inactive tonight is not counted.
    """
    expired = {
        (tr.get("name") or "").lower(): tr
        for tr in (time_ranges or [])
        if time_range_is_expired(tr, now)
    }
    if not expired:
        return []
    dead: List[Dict[str, Any]] = []
    for raw in rules:
        parsed = parse_acl_rule(raw, switch_type, object_group_types)
        if not parsed:
            continue
        name = (parsed.get("time_range") or "").lower()
        if name not in expired:
            continue
        dead.append({
            # The original line, not parsed["raw"] -- parse_acl_rule strips the
            # sequence number off, and the sequence is what the operator needs
            # both to recognise the rule and to remove it.
            "raw": raw.strip(),
            "sequence": _sequence_of(raw),
            "time_range": parsed.get("time_range"),
            "entries": (expired[name] or {}).get("entries") or [],
        })
    return dead

def find_wrong_direction_rules(
    rules: List[str],
    bindings: List[Dict[str, str]],
    interface_subnets: Dict[str, str],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
    address_groups: Optional[Dict[str, List[str]]] = None,
) -> List[Dict[str, Any]]:
    """
    Flag rules that can never match real traffic through ANY of the VLAN
    interfaces this ACL is actually applied to: for an inbound binding,
    the rule's source must plausibly originate on that VLAN (be "any", or
    overlap its subnet — directly or through an object-group's members);
    for outbound, the same check applies to the destination. A rule is
    only flagged if it fails this check for every applicable binding —
    passing for just one binding (e.g. the ACL is also applied elsewhere)
    is enough to be considered fine everywhere.

    Bindings whose interface's subnet is unknown are skipped (nothing to
    check against). If none of the ACL's bindings have a known subnet,
    nothing is flagged — there's no basis to judge it.
    """
    address_groups = address_groups or {}
    usable = [(b["interface"], b["direction"]) for b in bindings
             if b["interface"] in interface_subnets]
    if not usable:
        return []

    checked_against = [
        {"interface": iface, "direction": direction, "subnet": interface_subnets[iface]}
        for iface, direction in usable
    ]

    parsed = []
    for raw in rules:
        p = parse_acl_rule(raw, switch_type, object_group_types, acl_kind)
        if p:
            p["_sequence"] = _sequence_of(raw)
            parsed.append(p)

    wrong = []
    for rule in parsed:
        ok = False
        for iface, direction in usable:
            side = "src" if direction == "in" else "dst"
            subnet = ipaddress.IPv4Network(interface_subnets[iface], strict=False)
            vlan_range = [(int(subnet.network_address), int(subnet.broadcast_address))]
            rule_range = _addr_range_list(rule, side, address_groups)
            if _ranges_overlap(rule_range, vlan_range):
                ok = True
                break
        if not ok:
            wrong.append({
                "raw": rule["raw"],
                "sequence": rule["_sequence"],
                "checked_against": checked_against,
            })
    return wrong


# ---------------------------------------------------------------------------
# VPC peer sync check
# ---------------------------------------------------------------------------

def _normalize_acl_line(line: str) -> str:
    """Strip display-only annotations ('show' output isn't config) and
    collapse whitespace, so a diff isn't tripped up by cosmetic differences
    like NX-OS hit counters ("[match=56]") or host/CIDR echo style, rather
    than an actual rule content difference."""
    value = re.sub(r"(?:\s+\([^)]*\)|\s+\[match=\d+\])+\s*$", "",
                   line.strip(), flags=re.IGNORECASE)
    value = re.sub(
        r"\bhost\s+(\d{1,3}(?:\.\d{1,3}){3})\b",
        lambda m: f"{m.group(1)}/32", value, flags=re.IGNORECASE)
    return " ".join(value.split()).lower()


def diff_acl_sets(acls_a: Dict[str, List[str]],
                   acls_b: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Compare every ACL's rule lines (sequence numbers included, since they're
    already part of each line) between two switches. Order matters for a
    real match (it reflects sequence order), so equality is checked on the
    normalized line lists directly; only the mismatch detail (only_in_a/b)
    uses set difference, purely to show *what* differs.
    """
    names = sorted(set(acls_a) | set(acls_b))
    results = []
    for name in names:
        a_lines = acls_a.get(name)
        b_lines = acls_b.get(name)
        if a_lines is None:
            results.append({"acl_name": name, "status": "missing_on_a",
                            "only_in_a": [], "only_in_b": list(b_lines or [])})
            continue
        if b_lines is None:
            results.append({"acl_name": name, "status": "missing_on_b",
                            "only_in_a": list(a_lines), "only_in_b": []})
            continue
        norm_a = [_normalize_acl_line(l) for l in a_lines]
        norm_b = [_normalize_acl_line(l) for l in b_lines]
        if norm_a == norm_b:
            results.append({"acl_name": name, "status": "match",
                            "only_in_a": [], "only_in_b": []})
            continue
        set_a, set_b = set(norm_a), set(norm_b)
        results.append({
            "acl_name": name, "status": "mismatch",
            "only_in_a": [l for l in a_lines if _normalize_acl_line(l) not in set_b],
            "only_in_b": [l for l in b_lines if _normalize_acl_line(l) not in set_a],
        })
    return results


def diff_vlan_acl_bindings(map_a: Dict[str, List[Dict[str, str]]],
                            map_b: Dict[str, List[Dict[str, str]]]
                            ) -> List[Dict[str, Any]]:
    """
    Compare ACL-to-VLAN-interface bindings between two switches. Inputs are
    {acl_name: [{"interface", "direction"}, ...]} (already filtered by the
    caller to VLAN/SVI interfaces only). Returns one entry per mismatched
    (acl_name, interface) pair - matches are omitted entirely.
    """
    def flat(m):
        out = {}
        for acl_name, rows in m.items():
            for row in rows:
                out[(acl_name, row["interface"])] = row["direction"]
        return out

    flat_a, flat_b = flat(map_a), flat(map_b)
    results = []
    for key in sorted(set(flat_a) | set(flat_b)):
        acl_name, interface = key
        dir_a, dir_b = flat_a.get(key), flat_b.get(key)
        if dir_a == dir_b:
            continue
        status = ("missing_on_a" if dir_a is None
                  else "missing_on_b" if dir_b is None
                  else "direction_mismatch")
        results.append({"acl_name": acl_name, "interface": interface,
                        "status": status, "direction_a": dir_a, "direction_b": dir_b})
    return results


# ---------------------------------------------------------------------------
# Summary rule suggester
# ---------------------------------------------------------------------------

def prefix_to_wildcard_str(prefix: int) -> str:
    bits = (0xFFFFFFFF >> prefix) & 0xFFFFFFFF
    return ".".join([str((bits >> (8 * i)) & 0xFF) for i in range(3, -1, -1)])


def _summary_is_nxos(switch_type: str) -> bool:
    return (switch_type or "ios").lower() in ("nexus", "nxos", "cisco_nxos")


def _summary_addr_operand(ip: str, wc: str, addrgroup: Optional[str], switch_type: str) -> str:
    """Mirrors rule_generator.ip_to_cisco_addr's conventions. Duplicated
    (not imported) because rule_generator itself imports from this module —
    importing back would be circular. Host/wildcard-mask formatting for a
    plain address is identical on both platforms; only the keyword for a
    group reference differs."""
    if addrgroup:
        keyword = "addrgroup" if _summary_is_nxos(switch_type) else "object-group"
        return f"{keyword} {addrgroup}"
    if ip == "any":
        return "any"
    if not wc or wc == "0.0.0.0":
        return f"host {ip}"
    return f"{ip} {wc}"


def _summary_port_operand(op: str, ports: List[int], portgroup: Optional[str],
                          switch_type: str) -> str:
    if portgroup:
        keyword = "portgroup" if _summary_is_nxos(switch_type) else "object-group"
        return f" {keyword} {portgroup}"
    if not op:
        return ""
    if op in ("eq", "neq", "lt", "gt"):
        return f" {op} {ports[0]}"
    if op == "range":
        return f" range {ports[0]} {ports[1]}"
    return ""


def _summary_protocol_token(rule: Dict[str, Any]) -> str:
    if rule.get("service_group"):
        # IOS service object-group occupies the protocol position.
        return f"object-group {rule['service_group']}"
    proto = rule["proto"]
    return "ip" if proto == "all" else proto


def _best_summary_network(networks: List[ipaddress.IPv4Network]
                          ) -> Optional[ipaddress.IPv4Network]:
    """
    Find the smallest CIDR block covering every given network, without
    landing the highest real address on that block's own broadcast address
    (unless the block is an exact, lossless fit — e.g. summarizing all 4
    addresses of a /30 as that /30 is fine, since nothing extra is added),
    and without covering drastically more addresses than are actually
    being summarized (a "useful" summary, not an overly broad one).
    Returns None if no such block exists within that margin.
    """
    if len(networks) < 2:
        return None
    lo = min(int(n.network_address) for n in networks)
    hi = max(int(n.broadcast_address) for n in networks)
    total_addrs = sum(n.num_addresses for n in networks)
    span = hi - lo + 1

    xor = lo ^ hi
    tightest_prefix = 32 - xor.bit_length() if xor else 32
    cap = max(8, total_addrs * 4)

    for prefix in range(tightest_prefix, -1, -1):
        block_size = 1 << (32 - prefix)
        if block_size > cap:
            return None
        network_int = lo & ~(block_size - 1) & 0xFFFFFFFF
        broadcast_int = network_int + block_size - 1
        exact = (block_size == total_addrs and span == total_addrs)
        if not exact and block_size > 1 and hi == broadcast_int:
            continue  # would land the highest real address on this block's broadcast
        return ipaddress.IPv4Network(f"{ipaddress.IPv4Address(network_int)}/{prefix}")
    return None


def _cluster_summary_networks(
    entries: List[Tuple[ipaddress.IPv4Network, Dict[str, Any]]]
) -> List[Tuple[ipaddress.IPv4Network, List[Dict[str, Any]]]]:
    """
    Greedily group same-proto/dst/port source networks (sorted by address)
    into one or more useful summary blocks, so a tightly clustered handful
    of hosts among many scattered ones still gets summarized instead of
    an all-or-nothing collapse over the whole set. Each returned block
    covers 2+ of the original rules.
    """
    ordered = sorted(entries, key=lambda e: int(e[0].network_address))
    results: List[Tuple[ipaddress.IPv4Network, List[Dict[str, Any]]]] = []
    i, n = 0, len(ordered)
    while i < n:
        cluster_nets = [ordered[i][0]]
        cluster_rules = [ordered[i][1]]
        best = None
        j = i + 1
        while j < n:
            candidate_nets = cluster_nets + [ordered[j][0]]
            candidate = _best_summary_network(candidate_nets)
            if candidate is None:
                break
            cluster_nets = candidate_nets
            cluster_rules = cluster_rules + [ordered[j][1]]
            best = candidate
            j += 1
        if best is not None and len(cluster_rules) >= 2:
            results.append((best, cluster_rules))
            i = j
        else:
            i += 1
    return results


def _widen_group_key(rule: Dict[str, Any], widen_side: str) -> tuple:
    """Key for grouping rules that differ ONLY in the widened side's
    address — every other field (protocol, both sides' ports, the other
    side's address, ICMP type, 'established', time-range) must match
    exactly. 'established' belongs here because merging an established
    rule with a plain one would silently widen the summary to admit
    connection setup the established rule never permitted."""
    other = "dst" if widen_side == "src" else "src"
    return (
        rule["proto"], rule.get("service_group"),
        rule[f"{other}_ip"], rule[f"{other}_wc"], rule[f"{other}_addrgroup"],
        rule[f"{other}_port_op"], tuple(rule[f"{other}_ports"]), rule[f"{other}_portgroup"],
        rule[f"{widen_side}_port_op"], tuple(rule[f"{widen_side}_ports"]),
        rule[f"{widen_side}_portgroup"],
        rule.get("icmp_type"), bool(rule.get("established")), rule.get("time_range"),
    )


def _extra_addresses(summary_net: ipaddress.IPv4Network,
                     original_networks: List[ipaddress.IPv4Network]) -> List[str]:
    """Every address inside summary_net that none of the original rules
    actually covered — the concrete cost of widening, shown so an admin
    can judge a suggestion instead of just trusting the note text."""
    covered = set()
    for net in original_networks:
        covered.update(int(a) for a in net)
    return [str(ipaddress.IPv4Address(i))
           for i in range(int(summary_net.network_address), int(summary_net.broadcast_address) + 1)
           if i not in covered]


def _suggest_widening(permit_rules: List[Dict[str, Any]], widen_side: str,
                      switch_type: str) -> List[Dict[str, Any]]:
    other = "dst" if widen_side == "src" else "src"
    suggestions = []

    groups: Dict[tuple, List[Dict]] = {}
    for rule in permit_rules:
        if rule[f"{widen_side}_addrgroup"] or rule[f"{widen_side}_ip"] == "any":
            continue  # can't widen a group reference or something already unbounded
        groups.setdefault(_widen_group_key(rule, widen_side), []).append(rule)

    for group in groups.values():
        if len(group) < 2:
            continue
        entries = []
        for r in group:
            try:
                wc = r[f"{widen_side}_wc"]
                prefix = wildcard_to_prefix(wc) if wc else 32
                net = ipaddress.IPv4Network(f"{r[f'{widen_side}_ip']}/{prefix}", strict=False)
                entries.append((net, r))
            except Exception:
                pass

        # A rule already covered by a wider rule's network in this same
        # group is an existing redundancy (Redundancy Checker's job), not
        # a summarization opportunity — drop it before clustering so it
        # can't distort the width-selection math for the others.
        all_nets = [net for net, _ in entries]
        entries = [(net, r) for net, r in entries
                  if not any(o != net and net.subnet_of(o) for o in all_nets)]
        if len(entries) < 2:
            continue

        for summary_net, cluster_rules in _cluster_summary_networks(entries):
            cluster_ids = {id(r) for r in cluster_rules}
            cluster_nets = {net for net, r in entries if id(r) in cluster_ids}
            # A block identical to one of the cluster's own inputs means one
            # existing rule already covers the others — that's Redundancy
            # Checker's job, not a genuinely new summary rule.
            if summary_net in cluster_nets:
                continue
            rep = cluster_rules[0]
            seq = min((r["_sequence"] for r in cluster_rules
                      if r["_sequence"] is not None), default=None)

            widened = _summary_addr_operand(
                str(summary_net.network_address),
                prefix_to_wildcard_str(summary_net.prefixlen), None, switch_type)
            widened += _summary_port_operand(
                rep[f"{widen_side}_port_op"], rep[f"{widen_side}_ports"],
                rep[f"{widen_side}_portgroup"], switch_type)
            fixed = _summary_addr_operand(
                rep[f"{other}_ip"], rep[f"{other}_wc"], rep[f"{other}_addrgroup"], switch_type)
            fixed += _summary_port_operand(
                rep[f"{other}_port_op"], rep[f"{other}_ports"],
                rep[f"{other}_portgroup"], switch_type)
            icmp_part = f" {rep['icmp_type']}" if rep.get("icmp_type") else ""
            # Every rule in the cluster shares this flag (it is part of the
            # grouping key), so carrying the representative's forward keeps
            # the summary exactly as narrow as the rules it replaces.
            est_part = " established" if rep.get("established") else ""
            tr_part = f" time-range {rep['time_range']}" if rep.get("time_range") else ""
            proto_tok = _summary_protocol_token(rep)

            operands = f"{widened} {fixed}" if widen_side == "src" else f"{fixed} {widened}"
            body = f"permit {proto_tok} {operands}{icmp_part}{est_part}{tr_part}"
            suggestion = f"{seq} {body}" if seq is not None else body

            extra = _extra_addresses(summary_net, list(cluster_nets))
            note = f"Summarizes {len(cluster_rules)} rules into {summary_net}"
            note += (f" — also permits {len(extra)} address(es) not in the original rules"
                    if extra else " — an exact match, no extra addresses added")
            note += " · verify before applying"

            suggestions.append({
                "suggestion": suggestion,
                "replaces": [f"{r['_sequence']} {r['raw']}" if r["_sequence"] is not None
                            else r["raw"] for r in cluster_rules],
                "widened_side": widen_side,
                "extra_addresses": extra,
                "note": note,
            })

    return suggestions


def suggest_summary_rules(
    acl_rules: List[str],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
) -> List[Dict[str, Any]]:
    """
    Suggest summary/supernet rules that replace 2+ permit rules — sharing
    everything except one side's address (source OR destination) — with a
    single wider rule, in the same CLI syntax and platform conventions Add
    ACL Rule uses (host/wildcard-mask addressing, addrgroup vs
    object-group keywords, IOS service-group handling). Each suggestion
    reports exactly which extra addresses (if any) it would newly permit
    beyond what the original rules covered, so it can be judged before
    applying. The new rule takes the lowest sequence number among the
    rules it replaces, so it keeps that rule's position in the ACL.
    """
    parsed = []
    for raw in acl_rules:
        p = parse_acl_rule(raw, switch_type, object_group_types, acl_kind)
        if p:
            p["_sequence"] = _sequence_of(raw)
            parsed.append(p)

    permit_rules = [p for p in parsed if p["action"] == "permit"]
    return (_suggest_widening(permit_rules, "src", switch_type)
           + _suggest_widening(permit_rules, "dst", switch_type))


# ---------------------------------------------------------------------------
# Reverse rule direction
# ---------------------------------------------------------------------------

def reverse_rule_direction(rule: Dict[str, Any], switch_type: str) -> Optional[str]:
    """
    Swap a parsed rule's source and destination operands — address (or
    object-group reference) and port qualifier together, as a pair — so a
    port that restricted the original source now restricts the new
    destination and vice versa. Protocol, ICMP type, and time-range are
    unaffected since they don't belong to either side.

    Returns None when the rule can't be safely auto-reversed: IOS
    overloads the same 'object-group' keyword for address groups AND
    service groups, and an IOS service-group's own members can encode a
    source/destination position independent of where the group sits in
    the rule text — swapping sides could silently misapply that position.
    Any object-group reference on IOS (address group on either side, or a
    service group in the protocol position) is excluded and left for
    manual review instead. NX-OS uses distinct, unambiguous addrgroup/
    portgroup keywords, so it has no such restriction.
    """
    is_nxos = _summary_is_nxos(switch_type)
    has_group_ref = bool(rule.get("src_addrgroup") or rule.get("dst_addrgroup")
                         or rule.get("service_group") or rule.get("src_portgroup")
                         or rule.get("dst_portgroup"))
    if not is_nxos and has_group_ref:
        return None

    new_src = _summary_addr_operand(rule["dst_ip"], rule["dst_wc"], rule["dst_addrgroup"], switch_type)
    new_src += _summary_port_operand(
        rule["dst_port_op"], rule["dst_ports"], rule["dst_portgroup"], switch_type)
    new_dst = _summary_addr_operand(rule["src_ip"], rule["src_wc"], rule["src_addrgroup"], switch_type)
    new_dst += _summary_port_operand(
        rule["src_port_op"], rule["src_ports"], rule["src_portgroup"], switch_type)

    proto_tok = _summary_protocol_token(rule)
    icmp_part = f" {rule['icmp_type']}" if rule.get("icmp_type") else ""
    # Preserved rather than dropped: losing 'established' would silently
    # broaden the reversed rule from return-traffic-only to full access,
    # including connection setup.
    est_part = " established" if rule.get("established") else ""
    tr_part = f" time-range {rule['time_range']}" if rule.get("time_range") else ""
    return f"{rule['action']} {proto_tok} {new_src} {new_dst}{icmp_part}{est_part}{tr_part}"


def plan_acl_reversal(
    rules: List[str],
    switch_type: str = "nexus",
    object_group_types: Optional[Dict[str, str]] = None,
    acl_kind: str = "extended",
) -> Dict[str, List[Dict[str, Any]]]:
    """
    For every permit/deny rule in an ACL, compute its direction-reversed
    form. Standard ACLs have no destination to swap with, so nothing is
    reversible for one. Non-rule lines (remarks) are left out entirely —
    they aren't touched either way. Returns:
      {"reversible": [{"sequence", "original", "reversed"}, ...],
       "manual": [{"sequence", "original", "reason"}, ...]}
    """
    if (acl_kind or "extended").lower() == "standard":
        return {"reversible": [], "manual": []}

    reversible: List[Dict[str, Any]] = []
    manual: List[Dict[str, Any]] = []
    for raw in rules:
        p = parse_acl_rule(raw, switch_type, object_group_types, acl_kind)
        if not p:
            continue
        seq = _sequence_of(raw)
        reversed_line = reverse_rule_direction(p, switch_type)
        if reversed_line is None:
            manual.append({
                "sequence": seq, "original": p["raw"],
                "reason": "References an IOS object-group — reverse it manually.",
            })
        else:
            reversible.append({"sequence": seq, "original": p["raw"], "reversed": reversed_line})
    return {"reversible": reversible, "manual": manual}


def _infer_ios_group_kinds(line: str) -> Dict[str, str]:
    """
    Templates have no live switch to fetch real object-group kinds from,
    but parse_acl_rule() requires an object_group_types dict to parse IOS
    'object-group NAME' references at all. IOS's grammar fully determines
    the *required* kind from where the token appears — protocol position
    (right after the action) must be a service/port group for the parse
    to proceed; any other position is an address group — so this builds
    exactly the self-consistent dict needed for structural parsing. It
    says nothing about whether that group actually exists anywhere; that
    is checked separately, against a real switch, at apply time.
    """
    tokens = re.sub(r"^\d+\s+", "", line.strip()).split()
    kinds: Dict[str, str] = {}
    if len(tokens) >= 3 and tokens[1].lower() == "object-group":
        kinds[tokens[2]] = "port"
    i = 0
    while i < len(tokens) - 1:
        if tokens[i].lower() == "object-group" and tokens[i + 1] not in kinds:
            kinds[tokens[i + 1]] = "address"
        i += 1
    return kinds


def reverse_template_line(line: str, switch_type: str, acl_kind: str = "extended"
                          ) -> Optional[str]:
    """
    Reverse one stored template rule line with no live switch involved —
    thin wrapper around parse_acl_rule()/reverse_rule_direction() using
    _infer_ios_group_kinds() for IOS (NX-OS's addrgroup/portgroup parsing
    doesn't require real group data; passing {} is already sufficient).
    Returns None under the same IOS-object-group exclusion rule Reverse
    Direction already enforces.

    A standard ACL rule has no destination to swap with, so "reversing"
    it is a no-op — the line is returned unchanged (matching
    plan_acl_reversal()'s treatment of standard ACLs).
    """
    if (acl_kind or "extended").lower() == "standard":
        return line
    is_nxos = _summary_is_nxos(switch_type)
    group_types = {} if is_nxos else _infer_ios_group_kinds(line)
    parsed = parse_acl_rule(line, switch_type, group_types, acl_kind)
    if not parsed:
        return None
    return reverse_rule_direction(parsed, switch_type)


def build_reversed_template_lines(lines: List[str], switch_type: str,
                                  acl_kind: str = "extended") -> Tuple[List[str], int]:
    """
    Map reverse_template_line() over every line in a template. Returns
    (reversed_lines, skipped_count) — skipped_count is how many lines
    couldn't be auto-reversed (IOS lines referencing an object-group),
    which the caller surfaces so the admin knows the other direction
    needs a separate, manually-authored template if they want it.
    """
    reversed_lines: List[str] = []
    skipped = 0
    for line in lines:
        r = reverse_template_line(line, switch_type, acl_kind)
        if r is None:
            skipped += 1
        else:
            reversed_lines.append(r)
    return reversed_lines, skipped


def first_empty_sequences(existing: List[int], count: int) -> List[int]:
    """
    Scan sequence numbers 1, 2, 3, ... in order and collect the first
    `count` not already used — the first empty slot(s) from the very top
    of the ACL, including any gap between existing rules.
    """
    used = set(existing)
    result: List[int] = []
    candidate = 1
    while len(result) < count:
        if candidate not in used:
            result.append(candidate)
        candidate += 1
    return result


# ---------------------------------------------------------------------------
# Object-group listing (both address and port groups)
# ---------------------------------------------------------------------------

def parse_object_groups(output: str, switch_type: str) -> List[Dict[str, Any]]:
    """
    Parse the output of ``show object-group`` using platform-specific headers.

    NX-OS:
      IPv4 address object-group NAME -> address
      Protocol port object-group NAME -> port

    IOS:
      Network object group NAME -> address
      Service object group NAME -> port

    A group's type comes only from its header. Member syntax is deliberately
    never used to infer or change the type.

    Returns a list of:
      {"name": str, "kind": "address"|"port", "members": [str, ...]}
    """
    platform = (switch_type or "ios").lower()
    is_nxos = platform in ("nexus", "nxos", "cisco_nxos")
    if is_nxos:
        headers = (
            (re.compile(r"^\s*IPv4\s+address\s+object-group\s+(\S+)\s*$",
                        re.IGNORECASE), "address"),
            (re.compile(r"^\s*Protocol\s+port\s+object-group\s+(\S+)\s*$",
                        re.IGNORECASE), "port"),
        )
    else:
        headers = (
            (re.compile(r"^\s*Network\s+object\s+group\s+(\S+)\s*$",
                        re.IGNORECASE), "address"),
            (re.compile(r"^\s*Service\s+object\s+group\s+(\S+)\s*$",
                        re.IGNORECASE), "port"),
        )

    groups: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        matched_header = False
        for pattern, kind in headers:
            m = pattern.match(line)
            if m:
                current = {"name": m.group(1), "kind": kind, "members": []}
                groups.append(current)
                matched_header = True
                break
        if matched_header:
            continue

        # Any other non-indented line ends the current group. This prevents
        # unrelated command output from being collected as members.
        if not re.match(r"^\s+\S", raw):
            current = None
            continue

        # Member line (indented under a group)
        if current is not None and re.match(r"^\s+\S", raw):
            member = line.strip()
            # Skip descriptive noise
            if not re.match(r"^(description|Description)\b", member):
                current["members"].append(member)

    return groups


# ---------------------------------------------------------------------------
# Time-range listing
# ---------------------------------------------------------------------------

def parse_time_ranges(output: str) -> List[Dict[str, Any]]:
    """
    Parse 'show time-range' output.

    Returns a list of:
      {"name": str, "status": "active"|"inactive"|"unknown",
       "entries": [str, ...]}
    
    Handles both IOS and NX-OS formats:
    - IOS: "time-range entry: NAME (active)" followed by "periodic daily..." or "absolute..."
    - NX-OS: "time-range entry: NAME (status)" followed by "10 absolute start..." on next line
    """
    ranges: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None

    for raw in output.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue

        # Match "time-range entry: NAME (status)" - both IOS and NX-OS use this format
        m = re.match(r"^\s*time-range\s+entry:\s*(\S+)\s*(?:\((\w+)\))?",
                     line, re.IGNORECASE)
        if m:
            status = (m.group(2) or "unknown").lower()
            if status not in ("active", "inactive"):
                status = "unknown"
            current = {"name": m.group(1), "status": status, "entries": []}
            ranges.append(current)
            continue

        # Alternative format: "time-range NAME" without "entry:" (less common)
        m = re.match(r"^\s*time-range\s+(\S+)(?:\s+\((\w+)\))?\s*$", line, re.IGNORECASE)
        if m:
            name = m.group(1)
            if name.lower() != "entry:":
                status = (m.group(2) or "unknown").lower() if m.group(2) else "unknown"
                if status not in ("active", "inactive"):
                    status = "unknown"
                current = {"name": name, "status": status, "entries": []}
                ranges.append(current)
                continue

        if current is not None:
            body = line.strip()
            
            # Skip common informational lines
            if re.match(r"^no entries listed$", body, re.IGNORECASE):
                current["status"] = "empty"
                continue
            if re.match(r"^used in: IP ACL entry$", body, re.IGNORECASE):
                continue
            
            # NX-OS format: "10 absolute start ... end ..."
            # IOS format: "absolute start ... end ..." or "periodic daily ..."
            # Match lines starting with optional sequence number, then absolute/periodic
            m = re.match(r"^(?:\d+\s+)?(absolute|periodic)\b(.*)$", body, re.IGNORECASE)
            if m:
                # Store the full entry (with or without sequence number)
                current["entries"].append(body)
                # Check if the entry itself contains active/inactive markers (with asterisk)
                # The asterisk (*) before "active" indicates the time-range is CURRENTLY active
                if re.search(r"\*\s*active\b", body, re.IGNORECASE):
                    current["status"] = "active"
                elif re.search(r"\*\s*inactive\b", body, re.IGNORECASE):
                    if current["status"] == "unknown":
                        current["status"] = "inactive"
                continue
            
            # Check for active/inactive status markers in other lines (with asterisk)
            if re.search(r"\*\s*active\b", body, re.IGNORECASE):
                current["status"] = "active"
            elif re.search(r"\*\s*inactive\b", body, re.IGNORECASE):
                if current["status"] == "unknown":
                    current["status"] = "inactive"

    return ranges


def parse_time_range_names(output: str) -> List[str]:
    """Extract just the time-range names from a running-config fragment."""
    names = []
    for m in re.finditer(r"^\s*time-range\s+(\S+)", output, re.MULTILINE | re.IGNORECASE):
        n = m.group(1)
        if n.lower() != "entry:" and n not in names:
            names.append(n)
    return names


def parse_time_range_config(output: str, name: str) -> List[str]:
    """Extract only restorable configuration commands for one time range."""
    commands: List[str] = []
    header = re.compile(
        rf"^\s*time-range\s+{re.escape(name)}\s*$", re.IGNORECASE)
    entry = re.compile(r"^\s*((?:\d+\s+)?(?:absolute|periodic)\b.*)$",
                       re.IGNORECASE)
    found = False
    for raw in output.splitlines():
        if header.match(raw):
            commands = [f"time-range {name}"]
            found = True
            continue
        if not found:
            continue
        match = entry.match(raw)
        if match:
            commands.append(match.group(1).strip())
        elif raw.strip() and not raw[:1].isspace():
            break
    return commands


# ---------------------------------------------------------------------------
# Undo helpers
# ---------------------------------------------------------------------------

def invert_config_commands(commands: List[str]) -> List[str]:
    """
    Build the inverse of a list of config commands so a change can be undone.

    · 'ip access-list extended X' is a context line — kept as-is.
    · '<seq> permit ...' → 'no <seq>'
    · 'no <seq>'         → cannot be auto-restored (caller must supply the
                           original text); represented as a comment marker.
    · 'time-range X'     → context line, kept
    · 'periodic ...' / 'absolute ...' → 'no periodic ...' / 'no absolute ...'
    """
    out: List[str] = []
    for cmd in commands:
        c = cmd.strip()
        if not c:
            continue
        low = c.lower()
        if low.startswith("ip access-list") or low.startswith("time-range"):
            out.append(c)
            continue
        if low.startswith("no "):
            # Removal cannot be inverted without the original line
            continue
        m = re.match(r"^(\d+)\s+", c)
        if m:
            out.append(f"no {m.group(1)}")
            continue
        out.append(f"no {c}")
    return out


# ── Object-group resolution (pure) ──

_NESTED_GROUP_LINE = re.compile(r"^\s*(?:\d+\s+)?group-object\s+(\S+)\s*$",
                                re.IGNORECASE)


def expand_nested_group_members(name: str,
                                groups_by_name: Dict[str, Dict[str, Any]],
                                _seen: Optional[set] = None) -> List[str]:
    """Recursively inline `group-object <name>` references into their target
    group's own raw member lines, so downstream address/port parsing sees the
    fully-resolved member set instead of silently skipping the reference line.
    Pure in-memory recursion over an already-fetched group list. Cycle-guarded
    in case of a misconfigured reference loop."""
    seen = (_seen or set()) | {name.lower()}
    group = groups_by_name.get(name.lower())
    if not group:
        return []
    expanded: List[str] = []
    for member in group["members"]:
        m = _NESTED_GROUP_LINE.match(member)
        if m:
            if m.group(1).lower() not in seen:
                expanded.extend(
                    expand_nested_group_members(m.group(1), groups_by_name, seen))
        else:
            expanded.append(member)
    return expanded


def build_group_maps(groups_list: List[Dict[str, Any]]
                     ) -> Tuple[Dict[str, str], Dict[str, List[str]],
                                Dict[str, List[Tuple]]]:
    """
    Resolve every object group's members into IP/port ranges, so a rule
    referencing one group can be found to cover a rule referencing a
    *different* group whose members are a subset.

    Returns (group_types, address_groups, service_groups) — the triple every
    group-aware analyzer in this module expects.
    """
    group_types = {g["name"]: g["kind"] for g in groups_list}
    groups_by_name = {g["name"].lower(): g for g in groups_list}
    address_groups = {
        g["name"]: parse_object_group_addresses(
            "\n".join(expand_nested_group_members(g["name"], groups_by_name)))
        for g in groups_list if g["kind"] == "address"
    }
    service_groups = {
        g["name"]: parse_object_group_services(
            "\n".join(expand_nested_group_members(g["name"], groups_by_name)))
        for g in groups_list if g["kind"] == "port"
    }
    return group_types, address_groups, service_groups


def parse_acl_interface_map(output: str) -> Dict[str, List[Dict[str, str]]]:
    """Map every ACL name to the interfaces and directions it is applied to,
    from a 'show running-config' dump."""
    mapping: Dict[str, List[Dict[str, str]]] = {}
    current_iface = None
    for line in (output or "").splitlines():
        m = re.match(r"^interface\s+(\S+)", line, re.IGNORECASE)
        if m:
            current_iface = m.group(1)
            continue
        m = re.search(r"ip\s+access-group\s+(\S+)\s+(in|out)", line, re.IGNORECASE)
        if m and current_iface:
            mapping.setdefault(m.group(1), []).append(
                {"interface": current_iface, "direction": m.group(2).lower()})
    return mapping


def vlan_bindings_only(mapping: Dict[str, List[Dict[str, str]]]
                       ) -> Dict[str, List[Dict[str, str]]]:
    """Keep only VLAN/SVI interfaces — the ones a VPC pair must agree on."""
    return {name: [row for row in rows
                   if re.match(r"^vlan\d+$", row["interface"], re.IGNORECASE)]
            for name, rows in (mapping or {}).items()}


# ── Schedule expiry (pure) ──

# IOS writes 'end 23:59 31 December 2024'; NX-OS writes the seconds too, as
# 'end 23:59:59 16 January 2025'. The seconds group is optional so one pattern
# reads both — without it every NX-OS end date silently fails to match.
_ABSOLUTE_END = re.compile(
    r"\bend\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s+(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})",
    re.IGNORECASE)

_MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6,
           "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}


def parse_absolute_end(entry: str) -> Optional[datetime]:
    """Return the end datetime of an `absolute ... end HH:MM D Month YYYY`
    entry, or None if the entry has no absolute end."""
    m = _ABSOLUTE_END.search(entry or "")
    if not m:
        return None
    month = _MONTHS.get(m.group(5)[:3].lower())
    if month is None:
        return None
    try:
        return datetime(int(m.group(6)), month, int(m.group(4)),
                        int(m.group(1)), int(m.group(2)),
                        int(m.group(3) or 0))
    except ValueError:
        return None


def time_range_is_expired(time_range: Dict[str, Any],
                          now: Optional[datetime] = None) -> bool:
    """
    True when a time range can never be active again.

    Deliberately stricter than "the switch does not report (active)": a
    `periodic weekdays 08:00 to 18:00` range is inactive every night without
    being stale, and counting those as expired would make a fleet view cry
    wolf on healthy configuration. A range is expired only when it has at
    least one entry, every entry is absolute with an end date, and every one
    of those end dates has passed.
    """
    entries = (time_range or {}).get("entries") or []
    if not entries:
        return False
    now = now or datetime.now()
    for entry in entries:
        if re.search(r"\bperiodic\b", entry, re.IGNORECASE):
            return False
        end = parse_absolute_end(entry)
        if end is None or end > now:
            return False
    return True
