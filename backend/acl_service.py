"""
ACL evaluation service — pure orchestration around acl_parser.
"""
from typing import Optional, Dict, Any, List

import acl_parser
import ssh_manager
import switch_service as svc
from switch_service import SwitchTarget


def _prefetch_groups(t: SwitchTarget, username: str):
    """Load all groups once, preserving IOS service-member protocols."""
    addr: Dict[str, List[str]] = {}
    port: Dict[str, Any] = {}
    groups = svc.get_object_groups(t, username)
    kinds = {g["name"].lower(): g["kind"] for g in groups}
    for item in groups:
        members = "\n".join(item["members"])
        if item["kind"] == "address":
            addr[item["name"]] = acl_parser.parse_object_group_addresses(members)
        else:
            port[item["name"]] = acl_parser.parse_object_group_services(members)
    return addr, port, kinds


def evaluate_interface(t: SwitchTarget, username: str, vlan: str,
                       user_src: str, user_dst: str, user_proto: str,
                       user_port: Optional[int], vlan_side: str,
                       user_icmp_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Evaluate all ACLs applied to one interface.
    vlan_side is 'src' or 'dst' — which of the user's IPs lives on this VLAN.
    """
    result: Dict[str, Any] = {
        "vlan": vlan,
        "vlan_belongs_to": vlan_side,
        "acl_applied": False,
        "acl_name": None,
        "acl_direction": None,
        "verdict": "PERMITTED",
        "verdict_reason": "No ACL is applied to this interface, so traffic is "
                          "permitted by default.",
        "matched_rule": None,
        "evaluated_acls": [],
        "expired_time_range_matches": [],
    }

    apps = svc.get_interface_acls(t, username, vlan)
    if not apps:
        return result

    # One fetch for every schedule on the switch, built on first need.
    # The per-rule check was a separate `show time-range <name>` for every
    # rule carrying one -- thirteen round trips on a seventy-rule ACL, at half
    # a second each, and the same name re-fetched every time it appeared.
    _schedules = {}

    def _is_active(name):
        if not _schedules:
            for entry in svc.get_time_ranges(t, username):
                _schedules[(entry.get("name") or "").lower()] = \
                    (entry.get("status") or "").lower() == "active"
            _schedules.setdefault("", True)
        return _schedules.get((name or "").lower(), True)

    for app in apps:
        acl_name  = app["acl_name"]
        direction = app["direction"]
        result.update({"acl_applied": True,
                       "acl_name": acl_name,
                       "acl_direction": direction})

        _, rule_lines = svc.get_acl_rules(t, username, acl_name)
        addr, port, group_types = _prefetch_groups(t, username)

        matched = None
        expired_matches = []
        
        for raw in rule_lines:
            parsed = acl_parser.parse_acl_rule(raw, t.type, group_types)
            if not parsed:
                continue
            
            # Check if rule has an expired time-range
            if parsed["time_range"]:
                is_active = _is_active(parsed["time_range"])
                if not is_active:
                    # Check if this rule WOULD match if the time-range was active
                    verdict = acl_parser.evaluate_rule(
                        rule=parsed, user_src=user_src, user_dst=user_dst,
                        user_proto=user_proto, user_port=user_port,
                        acl_direction=direction, vlan_ip_side=vlan_side,
                        addrgroup_ips=addr, portgroup_ports=port,
                        user_icmp_type=user_icmp_type)
                    if verdict is not None:
                        expired_matches.append({
                            "rule": raw,
                            "time_range": parsed["time_range"],
                            "action": ("PERMITTED" if verdict == "permit"
                                       else "DENIED")
                        })
                    continue
            
            verdict = acl_parser.evaluate_rule(
                rule=parsed, user_src=user_src, user_dst=user_dst,
                user_proto=user_proto, user_port=user_port,
                acl_direction=direction, vlan_ip_side=vlan_side,
                addrgroup_ips=addr, portgroup_ports=port,
                user_icmp_type=user_icmp_type)
            if verdict is not None:
                matched = (("PERMITTED" if verdict == "permit" else "DENIED"),
                           raw)
                break

        result["expired_time_range_matches"] = expired_matches
        
        result["evaluated_acls"].append({
            "acl_name": acl_name, "direction": direction,
            "rule_count": len(rule_lines),
            "matched_rule": matched[1] if matched else None,
            "verdict": matched[0] if matched else "DENIED",
        })

        if matched:
            verdict_reason = f"Matched a rule in ACL '{acl_name}' applied {direction}bound."
            if expired_matches:
                expired_permit = [m for m in expired_matches if m["action"] == "PERMITTED"]
                if expired_permit:
                    verdict_reason += (f" Note: This traffic also matched {len(expired_permit)} "
                                     f"expired time-range rule(s) that would have permitted it.")
            result.update({
                "verdict": matched[0],
                "matched_rule": matched[1],
                "verdict_reason": verdict_reason,
            })
            return result

        verdict_reason = (f"No rule in ACL '{acl_name}' ({direction}bound) "
                         f"matched this traffic, so the implicit deny at "
                         f"the end of the ACL applies.")
        if expired_matches:
            expired_permit = [m for m in expired_matches if m["action"] == "PERMITTED"]
            if expired_permit:
                verdict_reason += (f" Note: This traffic matched {len(expired_permit)} "
                                 f"expired time-range rule(s) that would have permitted it.")
        result.update({
            "verdict": "DENIED",
            "verdict_reason": verdict_reason,
        })
    return result


def side_not_on_switch(side: str, reason: str) -> Dict[str, Any]:
    return {"vlan": None, "vlan_belongs_to": side, "acl_applied": False,
            "acl_name": None, "acl_direction": None, "verdict": "N/A",
            "verdict_reason": reason, "matched_rule": None, "evaluated_acls": []}


def resolve_route(t: SwitchTarget, username: str, ip: str) -> Dict[str, Any]:
    """Run 'show ip route <ip>' and parse it."""
    host = ip.split("/")[0]
    out = svc.show(t, username, f"show ip route {host}", timeout=25)
    parsed = acl_parser.parse_route_output(out)
    parsed["raw"] = out
    return parsed


def port_to_int(port_spec: Optional[str]) -> Optional[int]:
    """Convert a validated port spec to a single int for matching."""
    if not port_spec:
        return None
    s = port_spec.strip()
    if s.lower().startswith("portgroup"):
        return None
    if "-" in s:
        s = s.split("-", 1)[0]
    if s.isdigit():
        return int(s)
    return acl_parser.resolve_port(s)
