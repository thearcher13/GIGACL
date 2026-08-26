"""Short-lived, authenticated interactive terminal workspace registry."""
from dataclasses import dataclass, field
import threading
import time
import uuid
from typing import Dict, List, Optional

from fastapi import HTTPException

import ssh_manager


PENDING_TTL_SECONDS = 30
MAX_TERMINALS_PER_USER = 3


@dataclass(frozen=True)
class TerminalTarget:
    switch_id: int
    label: str
    ip: str
    switch_type: str
    ssh_username: str
    password: str
    use_enable: bool
    enable_password: Optional[str]
    vpc_peer_id: Optional[int]


@dataclass
class TerminalWorkspace:
    id: str
    username: str
    targets: List[TerminalTarget]
    created_at: float = field(default_factory=time.monotonic)
    attached: bool = False
    connections: List[ssh_manager.SSHSession] = field(default_factory=list)


_workspaces: Dict[str, TerminalWorkspace] = {}
_by_user: Dict[str, set] = {}
_lock = threading.Lock()


def _target_from_service(target) -> TerminalTarget:
    return TerminalTarget(
        switch_id=target.id,
        label=target.label,
        ip=target.ip,
        switch_type=target.type,
        ssh_username=target.ssh_username,
        password=target.password,
        use_enable=target.use_enable,
        enable_password=target.enable_password,
        vpc_peer_id=target.sw.vpc_peer_id,
    )


def _remove_locked(workspace_id: str) -> Optional[TerminalWorkspace]:
    workspace = _workspaces.pop(workspace_id, None)
    if workspace:
        user_ids = _by_user.get(workspace.username)
        if user_ids is not None:
            user_ids.discard(workspace_id)
            if not user_ids:
                _by_user.pop(workspace.username, None)
    return workspace


def _disconnect(workspace: Optional[TerminalWorkspace]):
    if not workspace:
        return
    for connection in list(workspace.connections):
        connection.disconnect()
    workspace.connections.clear()


def _cleanup_expired_locked(now: float) -> List[TerminalWorkspace]:
    expired = [wid for wid, workspace in _workspaces.items()
               if not workspace.attached and
               now - workspace.created_at > PENDING_TTL_SECONDS]
    return [_remove_locked(wid) for wid in expired]


def reserve(username: str, targets) -> TerminalWorkspace:
    """Reserve up to three distinct switch terminals for a user."""
    copied = [_target_from_service(target) for target in targets]
    if len(copied) == 2:
        first, second = copied
        if (first.switch_type != "nexus" or second.switch_type != "nexus" or
                first.vpc_peer_id != second.switch_id or
                second.vpc_peer_id != first.switch_id):
            raise HTTPException(
                400, "Two terminals can only be opened for a configured VPC pair.")
    if len(copied) not in (1, 2):
        raise HTTPException(400, "Select one switch, or one configured VPC pair.")

    expired = []
    with _lock:
        expired = _cleanup_expired_locked(time.monotonic())
        active = [_workspaces[wid] for wid in _by_user.get(username, set())
                  if wid in _workspaces]
        active_switch_ids = {
            target.switch_id for workspace in active for target in workspace.targets}
        requested_ids = {target.switch_id for target in copied}
        duplicate_ids = active_switch_ids & requested_ids
        if duplicate_ids:
            duplicate = next(target.label for target in copied
                             if target.switch_id in duplicate_ids)
            raise HTTPException(
                409, f"A terminal for '{duplicate}' is already open. "
                     "Close it before opening that switch again.")
        if len(active_switch_ids) + len(requested_ids) > MAX_TERMINALS_PER_USER:
            raise HTTPException(
                409, "You can have at most three switch terminals open. "
                     "Close another terminal before opening this one.")
        workspace = TerminalWorkspace(id=uuid.uuid4().hex,
                                      username=username, targets=copied)
        _workspaces[workspace.id] = workspace
        _by_user.setdefault(username, set()).add(workspace.id)
    for old in expired:
        _disconnect(old)
    return workspace


def claim(workspace_id: str) -> Optional[TerminalWorkspace]:
    """Consume a pending workspace token. It can only attach once."""
    removed = None
    with _lock:
        workspace = _workspaces.get(workspace_id)
        if not workspace:
            return None
        if workspace.attached:
            return None
        if time.monotonic() - workspace.created_at > PENDING_TTL_SECONDS:
            removed = _remove_locked(workspace_id)
            workspace = None
        else:
            workspace.attached = True
    _disconnect(removed)
    return workspace


def register_connection(workspace: TerminalWorkspace,
                        connection: ssh_manager.SSHSession):
    with _lock:
        if _workspaces.get(workspace.id) is workspace:
            workspace.connections.append(connection)
            return
    connection.disconnect()


def close_owned(workspace_id: str, username: str) -> bool:
    with _lock:
        workspace = _workspaces.get(workspace_id)
        if not workspace or workspace.username != username:
            return False
        workspace = _remove_locked(workspace_id)
    _disconnect(workspace)
    return True


def release(workspace: TerminalWorkspace):
    with _lock:
        current = _workspaces.get(workspace.id)
        removed = _remove_locked(workspace.id) if current is workspace else None
    _disconnect(removed or workspace)


def reset_for_tests():
    """Clear process-local terminal state. Intended for isolated tests only."""
    with _lock:
        workspaces = list(_workspaces.values())
        _workspaces.clear()
        _by_user.clear()
    for workspace in workspaces:
        _disconnect(workspace)
