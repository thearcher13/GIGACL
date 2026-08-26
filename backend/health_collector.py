"""
Fleet health collection.

One switch, one pass, five show commands — then every analysis runs in memory
off that single payload.

This exists because the per-ACL analysis endpoints each fetch their own copy of
the same data: /api/analysis/redundant alone pulls the full running-config
twice (svc.map_acl_interfaces and svc.get_vlan_acl_bindings_and_subnets do not
share a fetch) and re-runs `show object-group` for every caller. Calling those
endpoints once per switch across a fleet would cost roughly twenty-five round
trips per switch. Every analyzer in acl_parser is pure, so the fix is simply to
fetch each distinct command once and hand the text to all of them.

Nothing here touches the database — it runs inside a worker thread, and the
caller owns persistence.
"""
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import acl_parser
import ssh_manager
import switch_service as svc
import tcam_parser
from database import (HEALTH_OK, HEALTH_PARTIAL, HEALTH_ERROR,
                      TCAM_OK, TCAM_UNSUPPORTED)

SHOW_ACLS          = "show ip access-lists"
SHOW_RUNNING       = "show running-config"
SHOW_OBJECT_GROUPS = "show object-group"
SHOW_TIME_RANGES   = "show time-range"

TIMEOUT_ACLS          = 40
TIMEOUT_RUNNING       = 90
TIMEOUT_OBJECT_GROUPS = 40
TIMEOUT_TIME_RANGES   = 30
TIMEOUT_TCAM          = 30

# check_redundant_rules is O(n²) over parsed rules with group resolution in the
# inner loop. A user runs it on one ACL; a sweep runs it on every ACL of every
# switch, holding the GIL while it does. Past this many rules on one switch the
# group-aware passes are skipped and the row is reported as partial, so one
# enormous ACL cannot stall the whole application.
MAX_RULES_FOR_DEEP_ANALYSIS = 3000


def _fetch(t: svc.SwitchTarget, username: str, command: str, timeout: int
           ) -> Tuple[str, Optional[str]]:
    """Run one show command. Returns (output, error) — never raises."""
    try:
        return svc.show(t, username, command, timeout=timeout), None
    except ssh_manager.SSHError as e:
        return "", str(e)
    except Exception as e:  # noqa: BLE001 - a sweep must survive anything
        return "", str(e)


def collect_tcam(t: svc.SwitchTarget, username: str) -> Dict[str, Any]:
    """
    Read ACL TCAM utilization, trying the other platform's command if the
    configured one is rejected.

    switch_type is user-supplied and never verified against the device, so the
    fallback both rescues a mislabelled switch and, when it succeeds, proves
    the mislabel: source != switch_type is the only validation the app has for
    that field.
    """
    first = tcam_parser.SOURCE_NEXUS if t.is_nexus else tcam_parser.SOURCE_IOS
    second = (tcam_parser.SOURCE_IOS if first == tcam_parser.SOURCE_NEXUS
              else tcam_parser.SOURCE_NEXUS)

    reason = None
    for source in (first, second):
        out, err = _fetch(t, username, tcam_parser.COMMAND_FOR[source],
                          TIMEOUT_TCAM)
        if err:
            reason = err
            continue
        # Safe here: TCAM output is short and structured. The same check must
        # not be run over a running-config, where a rule remark containing
        # "ERROR:" would be misread as a switch failure.
        switch_error = ssh_manager.detect_switch_error(out)
        if switch_error:
            reason = "The switch does not support this TCAM command."
            continue
        parsed = tcam_parser.parse_tcam_utilization(out, source)
        if parsed["status"] == tcam_parser.STATUS_OK:
            parsed["source"] = source
            return parsed
        reason = parsed["reason"]

    return {"status": TCAM_UNSUPPORTED, "reason": reason, "source": None,
            "ingress": {"used": None, "free": None, "max": None, "percent": None},
            "egress": {"used": None, "free": None, "max": None, "percent": None}}


def analyze(acls_out: str, running_out: str, groups_out: str,
            time_ranges_out: str, switch_type: str,
            now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Turn four raw show outputs into counts. Completely pure — this is where
    every number on the dashboard comes from, and it is testable without a
    switch, a socket, or a database.
    """
    all_rules = acl_parser.parse_all_acl_rules(acls_out or "")
    kinds = acl_parser.parse_acl_kinds(acls_out or "")
    bindings, subnets = acl_parser.parse_vlan_acl_bindings_and_subnets(
        running_out or "")
    groups_list = acl_parser.parse_object_groups(groups_out or "", switch_type)
    group_types, address_groups, service_groups = acl_parser.build_group_maps(
        groups_list)
    time_ranges = acl_parser.parse_time_ranges(time_ranges_out or "")

    rule_count = sum(len(lines) for lines in all_rules.values())
    too_large = rule_count > MAX_RULES_FOR_DEEP_ANALYSIS

    counts = {
        "acl_count": len(all_rules),
        "rule_count": rule_count,
        "object_group_count": len(groups_list),
        "redundant_count": 0,
        "trailing_redundant_count": 0,
        "wrong_direction_count": 0,
        "summarizable_count": 0,
        "summary_suggestion_count": 0,
        "analysis_skipped": too_large,
    }

    if not too_large:
        for name, lines in all_rules.items():
            kind = kinds.get(name, "extended")
            counts["redundant_count"] += sum(
                len(entry["redundant_rules"]) for entry in
                acl_parser.check_redundant_rules(
                    lines, switch_type, group_types, kind,
                    address_groups, service_groups))
            counts["trailing_redundant_count"] += sum(
                len(entry["redundant_rules"]) for entry in
                acl_parser.find_trailing_redundant_rules(
                    lines, switch_type, group_types, kind,
                    address_groups, service_groups))
            counts["wrong_direction_count"] += len(
                acl_parser.find_wrong_direction_rules(
                    lines, bindings.get(name, []), subnets,
                    switch_type, group_types, kind, address_groups))
            suggestions = acl_parser.suggest_summary_rules(
                lines, switch_type, group_types, kind)
            counts["summary_suggestion_count"] += len(suggestions)
            counts["summarizable_count"] += sum(
                len(s["replaces"]) for s in suggestions)

    expired_names = {
        tr["name"].lower() for tr in time_ranges
        if acl_parser.time_range_is_expired(tr, now)
    }
    counts["time_ranges_total"] = len(time_ranges)
    counts["time_ranges_inactive"] = sum(
        1 for tr in time_ranges if tr["status"] in ("inactive", "empty"))
    counts["time_ranges_expired"] = len(expired_names)

    # Rules pinned to a schedule that can never fire again — dead config, and
    # the number an operator can actually act on.
    dead = 0
    if expired_names:
        for lines in all_rules.values():
            for raw in lines:
                parsed = acl_parser.parse_acl_rule(raw, switch_type, group_types)
                if parsed and (parsed.get("time_range") or "").lower() in expired_names:
                    dead += 1
    counts["rules_with_dead_schedule"] = dead

    return counts


def collect_one(t: svc.SwitchTarget, username: str,
                now: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Collect one switch's health. Never raises.

    A count of zero is only meaningful when the fetch behind it succeeded, so
    the result carries a status: an unreachable switch reports 'error' rather
    than a tidy row of zeros that reads as a clean bill of health.
    """
    started = time.monotonic()
    result: Dict[str, Any] = {
        "switch_id": t.id, "switch_name": t.label, "switch_ip": t.ip,
        "switch_type": t.type, "status": HEALTH_OK, "error": None,
    }

    acls_out, err = _fetch(t, username, SHOW_ACLS, TIMEOUT_ACLS)
    if err:
        # The first failure means the session is unusable; the rest would only
        # repeat the same timeout.
        result.update(status=HEALTH_ERROR, error=err,
                      duration_ms=int((time.monotonic() - started) * 1000))
        result.update(_zero_counts())
        result.update(_tcam_columns(
            {"status": TCAM_UNSUPPORTED, "reason": None, "source": None,
             "ingress": {}, "egress": {}}))
        return result

    failed_sections: List[str] = []
    running_out, err = _fetch(t, username, SHOW_RUNNING, TIMEOUT_RUNNING)
    if err:
        failed_sections.append("running-config")
    groups_out, err = _fetch(t, username, SHOW_OBJECT_GROUPS,
                             TIMEOUT_OBJECT_GROUPS)
    if err:
        failed_sections.append("object groups")
    time_ranges_out, err = _fetch(t, username, SHOW_TIME_RANGES,
                                  TIMEOUT_TIME_RANGES)
    if err:
        failed_sections.append("time ranges")

    # Handed to the caller so a VPC pair can be diffed without either switch
    # being read a second time — the VPC Sync page pays for two more
    # running-config pulls to get this. Not columns; the caller drops them
    # before the row is written.
    result["_acl_map"] = acl_parser.parse_all_acl_rules(acls_out)
    result["_iface_map"] = acl_parser.parse_acl_interface_map(running_out)

    counts = analyze(acls_out, running_out, groups_out, time_ranges_out,
                     t.type, now)
    if counts.pop("analysis_skipped", False):
        failed_sections.append(
            f"rule analysis (over {MAX_RULES_FOR_DEEP_ANALYSIS} rules)")
    result.update(counts)

    tcam = collect_tcam(t, username)
    result.update(_tcam_columns(tcam))

    if failed_sections:
        result["status"] = HEALTH_PARTIAL
        result["error"] = "Could not read: " + ", ".join(failed_sections)
    result["duration_ms"] = int((time.monotonic() - started) * 1000)
    return result


def _zero_counts() -> Dict[str, int]:
    return {
        "acl_count": 0, "rule_count": 0, "object_group_count": 0,
        "redundant_count": 0, "trailing_redundant_count": 0,
        "wrong_direction_count": 0, "summarizable_count": 0,
        "summary_suggestion_count": 0, "time_ranges_total": 0,
        "time_ranges_inactive": 0, "time_ranges_expired": 0,
        "rules_with_dead_schedule": 0,
    }


def _tcam_columns(tcam: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten the parser's nested shape onto the snapshot's columns."""
    ingress = tcam.get("ingress") or {}
    egress = tcam.get("egress") or {}
    status = (TCAM_OK if tcam.get("status") == tcam_parser.STATUS_OK
              else TCAM_UNSUPPORTED)
    return {
        "tcam_status": status,
        "tcam_source": tcam.get("source"),
        "tcam_error": tcam.get("reason"),
        "tcam_max": ingress.get("max") or egress.get("max"),
        "tcam_in_used": ingress.get("used"),
        "tcam_in_free": ingress.get("free"),
        "tcam_in_pct": ingress.get("percent"),
        "tcam_out_used": egress.get("used"),
        "tcam_out_free": egress.get("free"),
        "tcam_out_pct": egress.get("percent"),
    }
