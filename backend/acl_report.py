"""
Plain-language ACL reporting.

Turns a parsed ACL into prose aimed at someone who cannot read ACL
syntax — a manager or auditor rather than a network engineer. Two
things make this more than a line-by-line translation:

1. ACLs are first-match-wins, so a rule that a preceding rule already
   covers never executes. Describing such a rule as if it were in force
   would actively mislead a reader who cannot check it themselves, so
   effective rules and dead ones are reported separately.
2. The implicit "deny everything else" at the end of every ACL is
   invisible in the config but is usually the single most important
   fact about it, so it is always stated.

Anything that cannot be parsed is reported verbatim in its own section
rather than dropped — a report claiming to cover every access must not
quietly omit lines it failed to understand.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional
import ipaddress
import re

import acl_parser


# Friendly descriptions for ports a non-technical reader is likely to meet.
# Falls back to acl_parser.NAMED_PORTS, then to a bare port number.
_FRIENDLY_PORTS: Dict[int, str] = {
    20: "FTP data transfer", 21: "FTP file transfer", 22: "SSH secure login",
    23: "Telnet (unencrypted login)", 25: "email sending (SMTP)",
    53: "DNS name lookups", 67: "DHCP address assignment", 68: "DHCP address assignment",
    69: "TFTP file transfer", 80: "web traffic (HTTP)", 110: "email retrieval (POP3)",
    123: "clock synchronisation (NTP)", 143: "email retrieval (IMAP)",
    161: "network monitoring (SNMP)", 162: "network monitoring traps (SNMP)",
    389: "directory lookups (LDAP)", 443: "secure web traffic (HTTPS)",
    445: "Windows file sharing (SMB)", 514: "system logging (syslog)",
    587: "email submission", 636: "secure directory lookups (LDAPS)",
    993: "secure email retrieval (IMAPS)", 995: "secure email retrieval (POP3S)",
    1433: "Microsoft SQL Server database", 1521: "Oracle database",
    3306: "MySQL database", 3389: "Windows Remote Desktop",
    5432: "PostgreSQL database", 5900: "VNC remote desktop",
    8080: "web traffic (alternate port)", 8443: "secure web traffic (alternate port)",
}

_PORT_NAMES: Dict[int, str] = {}
for _name, _num in acl_parser.NAMED_PORTS.items():
    _PORT_NAMES.setdefault(_num, _name)

_ICMP_PLAIN = {
    "echo": "ping requests", "echo-reply": "ping replies",
    "unreachable": "'destination unreachable' messages",
    "administratively-prohibited": "'blocked by policy' messages",
    "packet-too-big": "'packet too big' messages",
    "time-exceeded": "'time exceeded' messages",
    "redirect": "redirect messages", "traceroute": "traceroute messages",
}

_DAY_WORDS = {
    "monday": "Monday", "tuesday": "Tuesday", "wednesday": "Wednesday",
    "thursday": "Thursday", "friday": "Friday", "saturday": "Saturday",
    "sunday": "Sunday", "daily": "every day", "weekdays": "Monday to Friday",
    "weekend": "Saturday and Sunday",
}


def _plural(count: int, singular: str, plural: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def _verb(count: int, singular: str, plural: str) -> str:
    """Agree the verb with a count that _plural() has already rendered."""
    return singular if count == 1 else plural


def describe_port_number(port: int, proto: str = "", bare: bool = False) -> str:
    """A port as a lay reader would recognise it. `bare` drops the friendly
    service name, for places where naming the service reads oddly (a source
    port, which is about where traffic came from rather than what it is)."""
    label = f"{proto.upper()} port {port}" if proto else f"port {port}"
    if bare:
        return label
    friendly = _FRIENDLY_PORTS.get(port) or _PORT_NAMES.get(port)
    return f"{friendly} on {label}" if friendly else label


def describe_address(ip: str, wc: Optional[str], addrgroup: Optional[str]) -> str:
    """One address operand in plain words. Addresses are given as-is rather
    than dressed up ("192.168.10.97", not "the device at 192.168.10.97")."""
    if addrgroup:
        return f"any of the addresses in group \"{addrgroup}\""
    if ip == "any":
        return "any device"
    if not wc or wc == "0.0.0.0":
        return str(ip)
    try:
        prefix = acl_parser.wildcard_to_prefix(wc)
        net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
        if net.prefixlen == 32:
            return str(net.network_address)
        return (f"any address in {net} "
                f"({net.network_address}–{net.broadcast_address})")
    except Exception:
        # Non-contiguous or otherwise unusual mask: state it rather than guess.
        return f"addresses matching {ip} with mask {wc}"


def describe_ports(op: str, ports: List[int], portgroup: Optional[str],
                   proto: str = "", bare: bool = False) -> str:
    """A port qualifier in plain words; empty string when unrestricted."""
    if portgroup:
        return f"the ports in group \"{portgroup}\""
    if not op or not ports:
        return ""
    if op == "eq":
        return " or ".join(describe_port_number(p, proto, bare) for p in ports)
    if op == "neq":
        return ("any port except "
                + " or ".join(describe_port_number(p, proto, True) for p in ports))
    if op == "lt":
        return f"any port below {ports[0]}"
    if op == "gt":
        return f"any port above {ports[0]}"
    if op == "range" and len(ports) >= 2:
        label = f"{proto.upper()} ports" if proto else "ports"
        return f"{label} {ports[0]} to {ports[1]}"
    return ""


def describe_service(rule: Dict[str, Any]) -> str:
    """What kind of traffic the rule matches."""
    proto = (rule.get("proto") or "ip").lower()
    if rule.get("service_group"):
        return f"the ports in group \"{rule['service_group']}\""

    if proto == "icmp":
        icmp_type = rule.get("icmp_type")
        if icmp_type:
            return _ICMP_PLAIN.get(icmp_type, f"ICMP '{icmp_type}' messages")
        return "ping and other ICMP messages"
    if proto == "ip":
        return "any type of traffic"
    dst_ports = describe_ports(rule.get("dst_port_op", ""), rule.get("dst_ports") or [],
                               rule.get("dst_portgroup"), proto)
    return dst_ports or f"any {proto.upper()} traffic"


def describe_rule(rule: Dict[str, Any], has_earlier_rules: bool = False) -> Dict[str, Any]:
    """One parsed rule as a headline sentence plus qualifying notes. The
    object groups and schedules it names are returned alongside so the
    reader can jump from the sentence to their definitions.

    A deny only stops what no earlier rule already permitted (first match
    wins), so once there are rules above it that caveat is stated inline —
    without it a reader would take the block as absolute.
    """
    allowed = rule.get("action") == "permit"
    source = describe_address(rule.get("src_ip"), rule.get("src_wc"),
                              rule.get("src_addrgroup"))
    dest = describe_address(rule.get("dst_ip"), rule.get("dst_wc"),
                            rule.get("dst_addrgroup"))
    service = describe_service(rule)

    verb = "can reach" if allowed else "is blocked from reaching"
    # Trailing rather than infixed: the subject phrase varies ("192.168.1.5"
    # vs "Any of the addresses in group X"), and a trailing clause agrees
    # with all of them.
    unless = "" if allowed or not has_earlier_rules else \
        ", unless an earlier rule already allowed it"
    # Standard ACLs have no destination at all -- saying "can reach any
    # device" would invent a destination the rule never mentions.
    if rule.get("_standard"):
        text = (f"{source[0].upper()}{source[1:]} "
                f"{'is allowed' if allowed else 'is blocked'}{unless}.")
    else:
        text = f"{source[0].upper()}{source[1:]} {verb} {dest} using {service}{unless}."

    details: List[str] = []
    src_ports = describe_ports(rule.get("src_port_op", ""), rule.get("src_ports") or [],
                               rule.get("src_portgroup"),
                               (rule.get("proto") or ""), bare=True)
    if src_ports:
        details.append(f"The traffic must come from {src_ports}.")
    if rule.get("established"):
        details.append(
            "This only continues connections that were already opened — it cannot "
            "be used to start a new connection.")
    if rule.get("time_range"):
        details.append(f"Only in effect during the schedule \"{rule['time_range']}\".")

    groups = [g for g in (rule.get("src_addrgroup"), rule.get("dst_addrgroup"),
                          rule.get("service_group"), rule.get("src_portgroup"),
                          rule.get("dst_portgroup")) if g]
    seen, ordered = set(), []
    for g in groups:
        if g.lower() not in seen:
            seen.add(g.lower())
            ordered.append(g)
    schedules = [rule["time_range"]] if rule.get("time_range") else []
    return {"allowed": allowed, "text": text, "details": details,
            "groups": ordered, "schedules": schedules}


def describe_time_range_entry(entry: str) -> str:
    """Translate one time-range line into plain words, falling back to the
    original text when the shape is unfamiliar."""
    e = re.sub(r"^\s*\d+\s+", "", entry.strip())
    m = re.match(r"^periodic\s+(.+?)\s+(\d{1,2}:\d{2})\s+to\s+(?:(.+?)\s+)?(\d{1,2}:\d{2})\s*$",
                 e, re.IGNORECASE)
    if m:
        days_raw, start, end_days, end = m.groups()
        days = [_DAY_WORDS.get(d.lower(), d) for d in days_raw.split()]
        if len(days) == 1:
            day_text = days[0]
        else:
            day_text = ", ".join(days[:-1]) + " and " + days[-1]
        tail = f" (ending {_DAY_WORDS.get((end_days or '').lower(), end_days)})" if end_days else ""
        return f"{day_text}, {start} to {end}{tail}"
    m = re.match(r"^absolute(?:\s+start\s+(.+?))?(?:\s+end\s+(.+?))?\s*$", e, re.IGNORECASE)
    if m and (m.group(1) or m.group(2)):
        start, end = m.groups()
        if start and end:
            return f"from {start} until {end}"
        if start:
            return f"from {start} onwards"
        return f"until {end}"
    return e


_NETMASK_MEMBER = re.compile(r"^(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)$")


def describe_group_member(member: str, kind: str) -> str:
    """One object-group member line in plain words, so the appendix reads
    like addresses and ports rather than config syntax."""
    m = re.sub(r"^\s*\d+\s+", "", member.strip())
    if kind == "address":
        host = re.match(r"^host\s+(\S+)$", m, re.IGNORECASE)
        if host:
            return host.group(1)
        rng = re.match(r"^range\s+(\S+)\s+(\S+)$", m, re.IGNORECASE)
        if rng:
            return f"{rng.group(1)} to {rng.group(2)}"
        net = _NETMASK_MEMBER.match(m)
        if net:
            try:
                return str(ipaddress.IPv4Network(f"{net.group(1)}/{net.group(2)}",
                                                 strict=False))
            except Exception:
                return m
        return m
    # Service/port members: "tcp eq 443", "tcp-udp source eq 13000",
    # "tcp range 49152 65535", or a bare protocol.
    parts = m.split()
    if not parts:
        return m
    proto = parts[0].upper().replace("TCP-UDP", "TCP/UDP")
    rest = parts[1:]
    source = ""
    if rest and rest[0].lower() == "source":
        source = "source "
        rest = rest[1:]
    if not rest:
        return f"all {proto}"
    if rest[0].lower() == "eq" and len(rest) >= 2:
        labels = []
        for tok in rest[1:]:
            # Config often names the port ("tcp eq www"); resolve it so the
            # reader sees the number and the service, not the keyword.
            num = acl_parser.resolve_port(tok)
            if not num:
                labels.append(f"{proto} {source}port {tok}")
                continue
            friendly = _FRIENDLY_PORTS.get(num) or _PORT_NAMES.get(num)
            label = f"{proto} {source}port {num}"
            labels.append(f"{friendly} on {label}" if friendly else label)
        return " or ".join(labels)
    if rest[0].lower() == "range" and len(rest) >= 3:
        return f"{proto} {source}ports {rest[1]} to {rest[2]}"
    return m


def build_acl_report(acl_name: str, switch_label: str, switch_type: str,
                     acl_kind: str, rule_lines: List[str],
                     groups_list: List[Dict[str, Any]],
                     expanded_members: Dict[str, List[str]],
                     time_ranges: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Assemble the full structured report. Pure: every switch read has
    already happened, so this is straightforward to test."""
    group_types = {g["name"]: g["kind"] for g in groups_list}

    parsed: List[Dict[str, Any]] = []
    unparsed: List[str] = []
    is_standard = (acl_kind or "extended").lower() == "standard"
    for raw in rule_lines:
        stripped = re.sub(r"^\s*\d+\s+", "", raw.strip())
        if not stripped or stripped.lower().startswith("remark"):
            continue
        p = acl_parser.parse_acl_rule(raw, switch_type, group_types, acl_kind)
        if not p:
            unparsed.append(raw.strip())
            continue
        p["_sequence"] = acl_parser._sequence_of(raw)
        p["_standard"] = is_standard
        parsed.append(p)

    allowed: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    for i, rule in enumerate(parsed):
        described = describe_rule(rule, has_earlier_rules=i > 0)
        described["sequence"] = rule.get("_sequence")
        (allowed if described["allowed"] else blocked).append(described)

    # Does the ACL end with an explicit catch-all, or rely on the invisible
    # implicit deny? Either way the reader is told what happens by default.
    catch_all = None
    for rule in reversed(parsed):
        if (rule.get("src_ip") == "any" and rule.get("dst_ip") == "any"
                and (rule.get("proto") or "ip") == "ip"
                and not rule.get("time_range")):
            catch_all = rule
            break
    if catch_all is not None and catch_all.get("action") == "permit":
        default_action = ("Anything not described above is ALLOWED, because this ACL "
                          "ends with a rule that permits all remaining traffic.")
    elif catch_all is not None:
        default_action = ("Anything not described above is BLOCKED by the final "
                          "catch-all rule in this ACL.")
    else:
        default_action = ("Anything not described above is BLOCKED. Every ACL ends "
                          "with an invisible \"deny everything else\" rule, even "
                          "though it does not appear in the configuration.")

    # Only groups the rules actually name are worth listing, including any
    # pulled in transitively by a nested group-object reference.
    referenced: set = set()
    pending = [g for item in (allowed + blocked) for g in item["groups"]]
    while pending:
        name = pending.pop()
        if name.lower() in referenced:
            continue
        referenced.add(name.lower())
        src = next((g for g in groups_list if g["name"].lower() == name.lower()), None)
        for member in (src or {}).get("members", []):
            nested = re.match(r"^\s*(?:\d+\s+)?group-object\s+(\S+)\s*$", member,
                              re.IGNORECASE)
            if nested:
                pending.append(nested.group(1))

    groups_out = []
    emitted: set = set()
    for g in groups_list:
        if g["name"].lower() not in referenced or g["name"].lower() in emitted:
            continue
        emitted.add(g["name"].lower())
        members = expanded_members.get(g["name"], [])
        groups_out.append({
            "name": g["name"],
            "kind": "addresses" if g["kind"] == "address" else "ports",
            "kind_singular": "address" if g["kind"] == "address" else "port",
            "count": len(members),
            "members": [describe_group_member(m, g["kind"]) for m in members],
            "nested": [re.sub(r"^\s*(?:\d+\s+)?group-object\s+", "", m).strip()
                       for m in g["members"]
                       if re.match(r"^\s*(?:\d+\s+)?group-object\s", m, re.IGNORECASE)],
        })

    used_ranges = {r["time_range"].lower() for r in parsed if r.get("time_range")}
    ranges_out = [{
        "name": tr["name"],
        "status": tr.get("status", "unknown"),
        "description": [describe_time_range_entry(e) for e in tr.get("entries", [])],
    } for tr in time_ranges if tr["name"].lower() in used_ranges]

    return {
        "acl_name": acl_name,
        "switch_label": switch_label,
        "switch_type": "NX-OS" if switch_type == "nexus" else "IOS",
        "acl_kind": (acl_kind or "extended").lower(),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "summary": {
            "total": len(parsed),
            "allowed": len(allowed),
            "blocked": len(blocked),
        },
        "allowed": allowed,
        "blocked": blocked,
        "default_action": default_action,
        # Being permitted here is necessary but not sufficient: the traffic
        # still has to clear every other list along the way.
        "scope_note": ("This covers only this one access list. Traffic allowed here "
                       "can still be blocked by another access list further along "
                       "its path to the destination."),
        "groups": groups_out,
        "time_ranges": ranges_out,
        "unparsed": unparsed,
    }


def _md_escape(text: str) -> str:
    """Neutralise the few characters that would otherwise be read as
    Markdown formatting inside prose (group names contain underscores)."""
    return re.sub(r"([\\`*_\[\]<>])", r"\\\1", str(text))


def _md_anchor(prefix: str, name: str) -> str:
    """Anchor matching the slug a Markdown renderer derives from the
    definition headings below ("### Group: NAME" -> "group-name"). The
    prefix keeps a group and a schedule of the same name distinct, and
    underscores/hyphens are preserved because renderers keep them."""
    return prefix + re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")


def _md_link_refs(text: str, item: Dict[str, Any]) -> str:
    """Link quoted group/schedule names to their definition headings. The
    text arrives already escaped, so the names are matched in their escaped
    form while the anchor is still derived from the real name."""
    for prefix, key in (("group-", "groups"), ("schedule-", "schedules")):
        for name in item.get(key, []):
            quoted = f'"{_md_escape(name)}"'
            text = text.replace(quoted, f'[{quoted}](#{_md_anchor(prefix, name)})')
    return text


def render_markdown(report: Dict[str, Any]) -> str:
    """The report as Markdown, for pasting into a wiki, ticket or PR."""
    s = report["summary"]
    L: List[str] = []
    add = L.append

    add(f"# Access Report — {_md_escape(report['acl_name'])}")
    add("")
    add(f"**Switch:** {_md_escape(report['switch_label'])} "
        f"({report['switch_type']})  ")
    add(f"**Generated:** {report['generated_at']}")
    add("")
    add("## In short")
    add("")
    add(f"This list contains {_plural(s['total'], 'rule')}. "
        f"{_plural(s['allowed'], 'rule')} {_verb(s['allowed'], 'allows', 'allow')} access; "
        f"{_plural(s['blocked'], 'rule')} {_verb(s['blocked'], 'blocks', 'block')} access.")
    add("")
    add(f"> **{_md_escape(report['default_action'])}**")
    add(">")
    add(f"> {_md_escape(report['scope_note'])}")
    add("")

    def section(title: str, items: List[Dict[str, Any]], empty: str) -> None:
        add(f"## {title}")
        add("")
        if not items:
            add(f"_{empty}_")
            add("")
            return
        for n, item in enumerate(items, start=1):
            seq = (f"`rule {item['sequence']}` " if item.get("sequence") is not None else "")
            add(f"{n}. {seq}{_md_link_refs(_md_escape(item['text']), item)}")
            for d in item.get("details", []):
                add(f"   - {_md_link_refs(_md_escape(d), item)}")
        add("")

    section("What is allowed", report["allowed"], "Nothing is explicitly allowed.")
    section("What is blocked", report["blocked"], "Nothing is explicitly blocked.")

    if report["unparsed"]:
        add("## Lines that could not be translated")
        add("")
        add("Shown exactly as configured so nothing is left out:")
        add("")
        add("```")
        for line in report["unparsed"]:
            add(line)
        add("```")
        add("")

    if report["time_ranges"]:
        add("## Schedules used")
        add("")
        for tr in report["time_ranges"]:
            add(f"### Schedule: {_md_escape(tr['name'])}")
            add("")
            add(f"_Currently {tr['status']}._")
            add("")
            for d in tr["description"]:
                add(f"- {_md_escape(d)}")
            add("")

    if report["groups"]:
        add("## Group definitions")
        add("")
        add("Groups are named lists used by the rules above.")
        add("")
        for g in report["groups"]:
            add(f"### Group: {_md_escape(g['name'])}")
            add("")
            add(f"_{_plural(g['count'], g['kind_singular'], g['kind'])}_"
                + (" — includes "
                   + ", ".join(f"[{_md_escape(n)}](#{_md_anchor('group-', n)})"
                               for n in g["nested"])
                   if g["nested"] else ""))
            add("")
            for m in g["members"]:
                add(f"- `{m}`")
            add("")

    add("---")
    add("")
    add("_Rules are checked from top to bottom and the first match wins._")
    return "\n".join(L)


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def group_anchor(name: str) -> str:
    """Stable HTML id for a group's entry in the definitions section."""
    return "grp-" + re.sub(r"[^A-Za-z0-9_.-]", "-", name).lower()


def schedule_anchor(name: str) -> str:
    """Stable HTML id for a schedule's entry in the schedules section."""
    return "sch-" + re.sub(r"[^A-Za-z0-9_.-]", "-", name).lower()


def _link_refs(escaped_text: str, item: Dict[str, Any]) -> str:
    """Turn the quoted group and schedule names inside an already-escaped
    sentence into links down to their definitions, so a reader can follow a
    reference instead of scrolling to find it."""
    for name in item.get("groups", []):
        quoted = f"&quot;{_esc(name)}&quot;"
        escaped_text = escaped_text.replace(
            quoted, f'<a class="ref-link" href="#{group_anchor(name)}">{quoted}</a>')
    for name in item.get("schedules", []):
        quoted = f"&quot;{_esc(name)}&quot;"
        escaped_text = escaped_text.replace(
            quoted, f'<a class="ref-link" href="#{schedule_anchor(name)}">{quoted}</a>')
    return escaped_text


def render_html(report: Dict[str, Any]) -> str:
    """The report as a self-contained HTML page, for presenting or printing."""
    s = report["summary"]
    P: List[str] = []
    add = P.append
    add("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    add(f"<title>Access Report — {_esc(report['acl_name'])}</title>")
    add("""<style>
 body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
      max-width:820px;margin:40px auto;padding:0 20px;color:#1a1a1a}
 h1{font-size:22px;margin-bottom:4px} h2{font-size:16px;margin-top:32px;
      border-bottom:2px solid #e5e5e5;padding-bottom:6px}
 .meta{color:#666;font-size:13px;margin-bottom:24px}
 .short{background:#f5f7fa;border-left:4px solid #4a7fd4;padding:14px 18px;border-radius:4px}
 .default{font-weight:600;margin-top:10px}
 .scope{color:#555;font-size:13px;margin-top:8px}
 ol{padding-left:22px} li{margin-bottom:12px}
 .seq{color:#888;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace}
 .detail{color:#555;font-size:13.5px;margin-top:4px}
 .grp{margin-bottom:14px;scroll-margin-top:14px}
 .grp:target{background:#fff6d9;outline:3px solid #fff6d9;border-radius:4px}
 .grp-name{font-weight:600}
 .ref-link{color:#1a56b8;text-decoration:none;font-weight:600}
 .ref-link:hover{text-decoration:none;opacity:.75}
 .members{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;
      color:#444;background:#fafafa;border:1px solid #eee;border-radius:4px;
      padding:8px 12px;margin-top:4px;white-space:pre-wrap}
 footer{margin-top:36px;color:#666;font-size:13px;border-top:1px solid #e5e5e5;padding-top:12px}
 @media print{body{margin:0}}
</style></head><body>""")
    add(f"<h1>Access Report — {_esc(report['acl_name'])}</h1>")
    add(f"<div class=\"meta\">Switch {_esc(report['switch_label'])} "
        f"({_esc(report['switch_type'])}) · generated {_esc(report['generated_at'])}</div>")

    add("<div class=\"short\">")
    add(f"<div>This list contains {_plural(s['total'], 'rule')}. "
        f"{_plural(s['allowed'], 'rule')} {_verb(s['allowed'], 'allows', 'allow')} access; "
        f"{_plural(s['blocked'], 'rule')} {_verb(s['blocked'], 'blocks', 'block')} "
        f"access.</div>")
    add(f"<div class=\"default\">{_esc(report['default_action'])}</div>")
    add(f"<div class=\"scope\">{_esc(report['scope_note'])}</div></div>")

    def section(title: str, items: List[Dict[str, Any]], empty: str) -> None:
        add(f"<h2>{_esc(title)}</h2>")
        if not items:
            add(f"<p>{_esc(empty)}</p>")
            return
        add("<ol>")
        for item in items:
            seq = (f"<span class=\"seq\">rule {item['sequence']}</span> "
                   if item.get("sequence") is not None else "")
            add(f"<li>{seq}{_link_refs(_esc(item['text']), item)}")
            for d in item.get("details", []):
                add(f"<div class=\"detail\">{_link_refs(_esc(d), item)}</div>")
            add("</li>")
        add("</ol>")

    section("What is allowed", report["allowed"], "Nothing is explicitly allowed.")
    section("What is blocked", report["blocked"], "Nothing is explicitly blocked.")

    if report["unparsed"]:
        add("<h2>Lines that could not be translated</h2>")
        add("<p>Shown exactly as configured so nothing is left out:</p>")
        add("<div class=\"members\">" + _esc("\n".join(report["unparsed"])) + "</div>")

    if report["time_ranges"]:
        add("<h2>Schedules used</h2>")
        for tr in report["time_ranges"]:
            add(f"<div class=\"grp\" id=\"{schedule_anchor(tr['name'])}\">"
                f"<span class=\"grp-name\">{_esc(tr['name'])}</span> "
                f"<span class=\"seq\">currently {_esc(tr['status'])}</span>")
            for d in tr["description"]:
                add(f"<div class=\"detail\">{_esc(d)}</div>")
            add("</div>")

    if report["groups"]:
        add("<h2>Group definitions</h2>")
        add("<p>Groups are named lists used by the rules above.</p>")
        for g in report["groups"]:
            add(f"<div class=\"grp\" id=\"{group_anchor(g['name'])}\">"
                f"<span class=\"grp-name\">{_esc(g['name'])}</span> "
                f"<span class=\"seq\">{g['count']} {_esc(g['kind'])}</span>")
            if g["nested"]:
                add("<div class=\"detail\">Includes group "
                    + ", ".join(f"<a class=\"ref-link\" href=\"#{group_anchor(n)}\">"
                                f"{_esc(n)}</a>" for n in g["nested"]) + "</div>")
            if g["members"]:
                add("<div class=\"members\">" + _esc("\n".join(g["members"])) + "</div>")
            add("</div>")

    add("<footer>Rules are checked from top to bottom and the first match wins.</footer>")
    add("</body></html>")
    return "\n".join(P)
