"""
Generate Cisco ACL rule CLI syntax for write operations.
"""
import ipaddress
import re
from typing import Optional, List, Tuple
from acl_parser import prefix_to_wildcard_str


def _is_nxos(switch_type: str) -> bool:
    return (switch_type or "ios").lower() in ("nexus", "nxos", "cisco_nxos")


def group_name(value: Optional[str], keyword: str) -> Optional[str]:
    """Return the name from an internal ``keyword NAME`` group reference."""
    if not value:
        return None
    parts = value.strip().split(None, 1)
    if len(parts) == 2 and parts[0].lower() == keyword:
        return parts[1]
    return None


def ip_to_cisco_addr(ip_str: str, switch_type: str = "nexus") -> str:
    """
    Convert user IP input to Cisco ACL address syntax.
    'any'                → 'any'
    'addrgroup Foo'      → 'addrgroup Foo'
    '192.168.1.1/32'     → 'host 192.168.1.1'
    '192.168.1.0/24'     → '192.168.1.0 0.0.0.255'
    '192.168.1.1'        → 'host 192.168.1.1'
    """
    if not ip_str:
        return "any"
    stripped = ip_str.strip().lower()
    if stripped == "any":
        return "any"
    address_group = group_name(ip_str, "addrgroup")
    if address_group:
        keyword = "addrgroup" if _is_nxos(switch_type) else "object-group"
        return f"{keyword} {address_group}"
    try:
        net = ipaddress.IPv4Network(ip_str.strip(), strict=False)
        if net.prefixlen == 32:
            return f"host {net.network_address}"
        wc = prefix_to_wildcard_str(net.prefixlen)
        return f"{net.network_address} {wc}"
    except ValueError:
        # treat as host
        return f"host {ip_str.strip()}"


def port_to_cisco_syntax(port_input: Optional[str]) -> str:
    """
    Convert port input to Cisco syntax.
    'portgroup Web_Ports' → ' portgroup Web_Ports'
    '80'                  → ' eq 80'
    '80-443'              → ' range 80 443'
    '' or None            → ''
    """
    if not port_input:
        return ""
    port_input = port_input.strip()
    if port_input.lower().startswith("portgroup "):
        return f" {port_input}"
    if "-" in port_input:
        parts = port_input.split("-", 1)
        return f" range {parts[0].strip()} {parts[1].strip()}"
    return f" eq {port_input}"


def generate_permit_rule(
    src_ip: str,
    dst_ip: str,
    proto: str,
    port: Optional[str],
    acl_direction: str,   # 'in' or 'out'
    vlan_ip_side: str,    # 'src' or 'dst' — which user-IP is on the VLAN
    switch_type: str = "nexus",
    time_range: Optional[str] = None,
    icmp_type: Optional[str] = None,
    established: bool = False,
) -> Tuple[str, str]:
    """
    Generate the correct permit rule syntax considering ACL direction.

    Returns (rule_syntax, explanation).

    For 'in' ACL: first IP in rule = VLAN side
    For 'out' ACL: second IP in rule = VLAN side

    The VLAN side determines which user IP goes first in the rule.

    ``established`` (TCP only) is applied per-line, not globally: the
    keyword matches only ACK/RST segments, so the rule carrying it
    permits return traffic and can never permit connection setup. It
    therefore belongs solely on the line where the user's DESTINATION
    (the service being reached) ends up in the source position — that
    line authorizes the server to answer. On the opposite line the
    user's source is first, which is the client opening the connection;
    adding ``established`` there would drop the initial SYN and break
    the very access being granted. Direction and VLAN side matter only
    insofar as they decide that ordering.
    """
    src_addr = ip_to_cisco_addr(src_ip, switch_type)
    dst_addr = ip_to_cisco_addr(dst_ip, switch_type)
    service_group = group_name(port, "portgroup")
    if service_group and not _is_nxos(switch_type):
        # IOS service groups replace the protocol token and appear before both
        # addresses. Their members define protocol, source/destination position,
        # operator and ports.
        protocol_syntax = f"object-group {service_group}"
        port_syntax = ""
        service_note = (f" IOS service object group '{service_group}' defines "
                        "the permitted protocol and port members.")
    else:
        protocol_syntax = proto.lower()
        if protocol_syntax == "all":
            protocol_syntax = "ip"
        port_syntax = port_to_cisco_syntax(port)
        service_note = ""

    # A requested service port belongs to the user's destination endpoint.
    # ACL direction can reorder the two address operands, so attach the port
    # before doing that reorder rather than always appending it to operand two.
    src_operand = src_addr
    dst_operand = f"{dst_addr}{port_syntax}"

    # Tracked explicitly rather than re-derived later: it is the single fact
    # that decides whether 'established' belongs on this line.
    if acl_direction == "in":
        # First IP = VLAN side
        if vlan_ip_side == "src":
            # VLAN side is source → first position
            dst_first = False
            rule = f"permit {protocol_syntax} {src_operand} {dst_operand}"
            explanation = (f"ACL is applied INBOUND on the source's VLAN interface. "
                           f"Source IP goes first in the rule.{service_note}")
        else:
            # VLAN side is destination → destination goes first
            dst_first = True
            rule = f"permit {protocol_syntax} {dst_operand} {src_operand}"
            explanation = (f"ACL is applied INBOUND on the destination's VLAN interface. "
                           f"Destination IP goes first in the rule (it is the VLAN side)."
                           f"{service_note}")
    else:  # out
        # Second IP = VLAN side
        if vlan_ip_side == "dst":
            # VLAN side is destination → destination goes second (normal order)
            dst_first = False
            rule = f"permit {protocol_syntax} {src_operand} {dst_operand}"
            explanation = (f"ACL is applied OUTBOUND on the destination's VLAN interface. "
                           f"Source IP is first, destination (VLAN side) is second."
                           f"{service_note}")
        else:
            # VLAN side is source → source goes second
            dst_first = True
            rule = f"permit {protocol_syntax} {dst_operand} {src_operand}"
            explanation = (f"ACL is applied OUTBOUND on the source's VLAN interface. "
                           f"Destination IP is first, source (VLAN side) is second."
                           f"{service_note}")

    # Cisco always places the ICMP message type after BOTH addresses,
    # regardless of which one ended up first due to ACL-direction reordering
    # above — it is never attached to a specific address operand.
    if protocol_syntax == "icmp" and icmp_type:
        rule += f" {icmp_type}"

    # Only on the return-path line, and only where the protocol token really
    # is tcp — an IOS service object-group replaces that token and defines
    # its own protocols, so 'established' is not attached to those.
    if established and protocol_syntax == "tcp":
        if dst_first:
            rule += " established"
            explanation += (" The destination is first here, so this line carries the "
                            "return traffic — 'established' limits it to replies within "
                            "a session the source already opened.")
        else:
            explanation += (" 'established' was NOT added here: the source is first, so "
                            "this line is what opens the connection, and the keyword "
                            "would drop the initial SYN.")

    if time_range:
        rule += f" time-range {time_range}"
        explanation += f" Access is limited by time-range '{time_range}'."

    return rule, explanation


def object_group_header(name: str, kind: str, switch_type: str = "ios") -> str:
    """Return the platform-specific 'object-group ...' creation/context line."""
    is_nxos = _is_nxos(switch_type)
    if kind == "address":
        return f"object-group ip address {name}" if is_nxos else f"object-group network {name}"
    return f"object-group ip port {name}" if is_nxos else f"object-group service {name}"


def object_group_address_member(prefix: Optional[str] = None,
                                 group_ref: Optional[str] = None,
                                 switch_type: str = "ios") -> str:
    """
    Build one address-group member line.
    A /32 (or a bare IP with no prefix length) becomes 'host A.B.C.D' on both
    platforms. Otherwise: NX-OS keeps 'A.B.C.D/LEN'; IOS uses a subnet mask
    ('A.B.C.D M.M.M.M') — object-group network members take a network mask,
    not the wildcard mask ACL rules use. Nesting via 'group-object NAME' is
    IOS-only.
    """
    is_nxos = _is_nxos(switch_type)
    if group_ref:
        if is_nxos:
            raise ValueError("Nested object-groups are not supported on NX-OS.")
        return f"group-object {group_ref}"
    if not prefix:
        raise ValueError("An address prefix or nested group is required.")
    net = ipaddress.IPv4Network(prefix, strict=False)
    if net.prefixlen == 32:
        return f"host {net.network_address}"
    if is_nxos:
        return str(net)
    return f"{net.network_address} {net.netmask}"


def object_group_port_member(protocol: Optional[str] = None,
                              group_ref: Optional[str] = None,
                              port: Optional[str] = None,
                              switch_type: str = "ios") -> str:
    """
    Build one port-group member line.
    NX-OS: 'eq N' / 'range LO HI' from the port only. Protocol and nesting are not supported.
    IOS: '<protocol> eq N' / '<protocol> range LO HI', or 'group-object NAME' to nest.
    """
    is_nxos = _is_nxos(switch_type)
    if group_ref:
        if is_nxos:
            raise ValueError("Nested object-groups are not supported on NX-OS.")
        return f"group-object {group_ref}"
    if not port:
        raise ValueError("A port or nested group is required.")
    if is_nxos and protocol:
        raise ValueError("A protocol cannot be set on an NX-OS port-group member.")
    if not is_nxos and not protocol:
        raise ValueError("A protocol (tcp, udp, or tcp-udp) is required on IOS.")

    # A numeric range is 'LO-HI'; anything else (a number or a named IOS
    # keyword such as 'ftp-data', which itself contains a hyphen) is a
    # single port used with 'eq'.
    m = re.match(r"^(\d+)-(\d+)$", port.strip())
    op_syntax = f"range {m.group(1)} {m.group(2)}" if m else f"eq {port.strip()}"

    return f"{protocol} {op_syntax}" if protocol else op_syntax


def strip_og_seq(line: str) -> str:
    """Strip a leading NX-OS sequence number from a stored object-group member line."""
    return re.sub(r"^\d+\s+", "", line.strip())


def get_next_sequence_number(acl_output: str) -> int:
    """Find the next available sequence number in an ACL."""
    import re
    seq_nums = [int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\s+(permit|deny)", acl_output, re.MULTILINE | re.IGNORECASE)]
    if not seq_nums:
        return 10
    return max(seq_nums) + 10


def build_time_range_commands(name: str, entries: list) -> List[str]:
    """
    Build CLI commands for creating a time-range.
    entries: list of dicts with keys:
      type: 'absolute' or 'periodic'
      For absolute: start_time, start_date, end_time, end_date
      For periodic: days, start_time, end_time
    Returns list of CLI lines.
    """
    cmds = [f"time-range {name}"]
    for entry in entries:
        if entry["type"] == "absolute":
            start = f"{entry.get('start_time', '')} {entry.get('start_date', '')}".strip()
            end = f"{entry.get('end_time', '')} {entry.get('end_date', '')}".strip()
            if start and end:
                cmds.append(f" absolute start {start} end {end}")
            elif start:
                cmds.append(f" absolute start {start}")
            elif end:
                cmds.append(f" absolute end {end}")
        elif entry["type"] == "periodic":
            days = entry.get("days", "daily")
            start_time = entry.get("start_time", "00:00")
            end_time = entry.get("end_time", "23:59")
            cmds.append(f" periodic {days} {start_time} to {end_time}")
    return cmds
