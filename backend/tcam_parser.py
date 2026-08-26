"""
TCAM utilization parsing.

Pure functions over already-fetched `show` output, like acl_parser — no I/O,
so every case below is unit-testable from a captured string.

Both platforms report how much of the ACL TCAM is consumed, but in different
shapes, and plenty of models report nothing at all. Nothing here raises: an
unreadable reply becomes status "unsupported", because a switch that cannot
report its TCAM is a normal switch, not a broken one.
"""
import re
from typing import Any, Dict, Optional

STATUS_OK          = "ok"
STATUS_UNSUPPORTED = "unsupported"

SOURCE_NEXUS = "nexus"
SOURCE_IOS   = "ios"

NXOS_COMMAND = "show hardware access-list resource utilization"
IOS_COMMAND  = ("show platform hardware fed switch active "
                "fwd-asic resource tcam utilization")

COMMAND_FOR = {SOURCE_NEXUS: NXOS_COMMAND, SOURCE_IOS: IOS_COMMAND}


def _blank_side() -> Dict[str, Optional[Any]]:
    return {"used": None, "free": None, "max": None, "percent": None}


def _unsupported(reason: str) -> Dict[str, Any]:
    return {"status": STATUS_UNSUPPORTED, "reason": reason,
            "ingress": _blank_side(), "egress": _blank_side()}


def _side(used: int, free: Optional[int], maximum: Optional[int],
          percent: float) -> Dict[str, Any]:
    return {"used": used, "free": free, "max": maximum, "percent": percent}


# ── NX-OS ──
# "Ingress RACL     1381     411     77.06"
# Some releases box the table in pipes, hence the optional separators.
_NXOS_ROW = re.compile(
    r"^\s*\|?\s*(Ingress|Egress)\s+RACL\s*\|?\s+"
    r"(\d+)\s*\|?\s+(\d+)\s*\|?\s+([\d.]+)\s*%?",
    re.IGNORECASE)


def parse_nxos_tcam_utilization(output: str) -> Dict[str, Any]:
    """
    Parse 'show hardware access-list resource utilization' (NX-OS).

    Columns are used, free, percent — the platform reports free rather than a
    maximum, so max is derived. A multi-module chassis prints the block once
    per module; the worst module wins, since that is the one that will refuse
    the next ACE.
    """
    sides: Dict[str, Dict[str, Any]] = {}
    for line in (output or "").splitlines():
        m = _NXOS_ROW.match(line)
        if not m:
            continue
        direction = m.group(1).lower()
        used, free = int(m.group(2)), int(m.group(3))
        try:
            percent = float(m.group(4))
        except ValueError:
            continue
        key = "ingress" if direction == "ingress" else "egress"
        previous = sides.get(key)
        if previous is None or percent > previous["percent"]:
            sides[key] = _side(used, free, used + free, percent)

    if not sides:
        return _unsupported("No TCAM rows found in the switch's reply.")
    return {"status": STATUS_OK, "reason": None,
            "ingress": sides.get("ingress") or _blank_side(),
            "egress": sides.get("egress") or _blank_side()}


# ── IOS ──
# Security ACL   TCAM   IO   5120   852   16.64%   747   60   0   45
#                TCAM   I           88    1.72%    12    36   0   40
#                TCAM   O           764   14.92%   735   24   0   5
#
# The I and O rows are unlabelled continuation lines, so they are only read
# inside a short window after the Security ACL header. Matching them globally
# would happily pick up an I/O pair belonging to some later resource block.
_IOS_HEADER = re.compile(
    r"Security\s+ACL\b.*?\bTCAM\b\s+IO\s+(\d+)\s+(\d+)\s+([\d.]+)\s*%",
    re.IGNORECASE)
_IOS_DIRECTION = re.compile(
    r"^\s*(?:\S.*?\s)?\bTCAM\b\s+([IO])\s+(\d+)\s+([\d.]+)\s*%",
    re.IGNORECASE)

_IOS_WINDOW = 4


def parse_ios_tcam_utilization(output: str) -> Dict[str, Any]:
    """
    Parse 'show platform hardware fed ... resource tcam utilization' (IOS-XE).

    The 'IO' row carries the bank size shared by both directions; the 'I' and
    'O' rows that follow carry the per-direction usage.
    """
    lines = [ln for ln in (output or "").splitlines() if ln.strip()]
    header_at = None
    maximum = None
    for i, line in enumerate(lines):
        m = _IOS_HEADER.search(line)
        if m:
            header_at = i
            maximum = int(m.group(1))
            break

    if header_at is None:
        return _unsupported("No Security ACL TCAM row found in the reply.")

    sides: Dict[str, Dict[str, Any]] = {}
    for line in lines[header_at + 1:header_at + 1 + _IOS_WINDOW]:
        if _IOS_HEADER.search(line):
            break  # A new resource block started; the window is over.
        m = _IOS_DIRECTION.match(line)
        if not m:
            continue
        used = int(m.group(2))
        try:
            percent = float(m.group(3))
        except ValueError:
            continue
        free = max(maximum - used, 0) if maximum is not None else None
        key = "ingress" if m.group(1).upper() == "I" else "egress"
        sides.setdefault(key, _side(used, free, maximum, percent))

    if not sides:
        # Half a reading is worse than an honest "unsupported" on a dashboard.
        return _unsupported(
            "Ingress and egress TCAM rows were not present in the reply.")
    return {"status": STATUS_OK, "reason": None,
            "ingress": sides.get("ingress") or _blank_side(),
            "egress": sides.get("egress") or _blank_side()}


def parse_tcam_utilization(output: str, source: str) -> Dict[str, Any]:
    """Dispatch to the parser for `source` ('nexus' or 'ios')."""
    if (source or "").lower() in ("nexus", "nxos", "cisco_nxos"):
        return parse_nxos_tcam_utilization(output)
    return parse_ios_tcam_utilization(output)
