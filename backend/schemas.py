"""
Pydantic request / response models.
"""
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ── auth ──
class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str
    mega: str = "byte"
    mega_visible: bool = False
    theme: str = "dark"

class UserCreate(BaseModel):
    username: str = Field(..., max_length=64)
    password: str
    role: str = "user"

class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    locked: bool = False
    locked_until: Optional[str] = None
    seconds_remaining: Optional[int] = None
    failed_attempts: int = 0
    trusted_hosts: Optional[str] = None
    mega: str = "byte"
    class Config: from_attributes = True

class RoleUpdate(BaseModel):
    role: str

class UsernameUpdate(BaseModel):
    username: str = Field(..., max_length=64)

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class AdminPasswordReset(BaseModel):
    new_password: str

class TrustedHostsUpdate(BaseModel):
    trusted_hosts: str  # Comma-separated IP prefixes

class MegaUpdate(BaseModel):
    mega: str = Field(..., min_length=1, max_length=32)

class ThemeUpdate(BaseModel):
    theme: str = Field(..., min_length=1, max_length=32)

class IdleTimeoutUpdate(BaseModel):
    idle_timeout_minutes: int

class LogRetentionUpdate(BaseModel):
    auto_delete_days: int
    auto_delete_zip: bool = False

class LogDeleteRequest(BaseModel):
    days: int
    zip: bool = False



# ── switches ──
class SwitchAdd(BaseModel):
    ip_address: str
    ssh_username: str
    ssh_password: str
    switch_type: str = "ios"
    site: Optional[str] = None
    use_enable: bool = False
    enable_password: Optional[str] = None  # Required when use_enable=True, saved encrypted
    save_password: bool = True

class SwitchUpdate(BaseModel):
    switch_id: int
    switch_type: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    site: Optional[str] = None
    use_enable: Optional[bool] = None
    enable_password: Optional[str] = None  # Required when use_enable=True

class SwitchResponse(BaseModel):
    id: int
    ip_address: str
    hostname: Optional[str]
    switch_type: Optional[str]
    site: Optional[str]
    use_enable: bool
    ssh_username: Optional[str]
    has_saved_password: bool
    vpc_peer_id: Optional[int] = None
    vpc_peer_name: Optional[str] = None
    pending_changes: bool = False
    # Set when a super admin added this switch for the holder. The holder can
    # use it but cannot edit or remove it.
    created_by: Optional[str] = None
    access_level: str = "write"
    terminal_access: bool = True
    class Config: from_attributes = True

class VpcPairRequest(BaseModel):
    switch_id: int
    peer_switch_id: Optional[int] = None

class SwitchOrderUpdate(BaseModel):
    labels: List[str] = Field(default_factory=list)
    switch_ids: List[int] = Field(default_factory=list)

class SiteAdd(BaseModel):
    name: str = Field(..., max_length=64)


# ── shared multi-switch base ──
class SwitchTargets(BaseModel):
    switch_ids: List[int] = Field(..., min_length=1)


# ── analysis ──
class ACLCheckRequest(SwitchTargets):
    src_ip: str
    dst_ip: str
    protocol: str
    port: Optional[str] = None
    icmp_type: Optional[str] = None

class IPACLCheckRequest(SwitchTargets):
    ip_address: str

class GlobalIPACLCheckRequest(BaseModel):
    ip_address: str

class AnalysisRequest(SwitchTargets):
    acl_name: str

class ObjectGroupRequest(SwitchTargets):
    pass

class TimeRangeListRequest(SwitchTargets):
    pass


# ── write ──
class RulePreviewRequest(SwitchTargets):
    src_ip: str
    dst_ip: str
    protocol: str
    port: Optional[str] = None
    icmp_type: Optional[str] = None
    established: bool = False
    time_range: Optional[str] = None
    remark: Optional[str] = None
    remark_sequence_number: Optional[int] = None
    sequence_number: Optional[int] = None

class RuleApplyRequest(BaseModel):
    switch_id: int
    acl_name: str
    rule_syntax: str
    remark: Optional[str] = None
    remark_sequence: Optional[int] = None

class RuleDeleteRequest(BaseModel):
    switch_id: int
    acl_name: str
    sequence_number: int

class AclReportRequest(BaseModel):
    switch_id: int
    acl_name: str

class AclDeleteRequest(BaseModel):
    switch_id: int
    acl_name: str

class AclSyncRequest(BaseModel):
    source_switch_id: int
    target_switch_id: int
    acl_name: str

class RuleCheckExistingRequest(BaseModel):
    switch_id: int
    acl_name: str
    rule_syntax: str

class RuleEditRequest(BaseModel):
    switch_id: int
    acl_name: str
    original_rule: str
    new_rule: str

class ACLInterfaceUpdateRequest(BaseModel):
    switch_id: int
    acl_name: str
    interface: str
    direction: str
    action: str

class ACLInterfaceFlipRequest(BaseModel):
    switch_id: int
    acl_name: str
    interface: str
    direction: str          # the direction it is applied in NOW

class SummaryApplyRequest(BaseModel):
    switch_id: int
    acl_name: str
    summary_rule: str
    rules_to_remove: List[int]

class ReverseDirectionRequest(BaseModel):
    switch_id: int
    acl_name: str

class ReverseDirectionApplyRequest(BaseModel):
    switch_id: int
    acl_name: str
    sequences: List[int]

class TemplateCreate(BaseModel):
    name: str = Field(..., max_length=64)
    switch_type: str
    acl_kind: str = "extended"
    direction: str
    lines: List[str]
    share_with: List[str] = []

class TemplateUpdate(TemplateCreate):
    pass

class TemplateApplyRequest(BaseModel):
    template_id: int
    switch_id: int
    acl_name: str
    direction: str

class AclCreateRequest(BaseModel):
    acl_name: str
    switch_id: int
    switch_type: str
    acl_kind: str = "extended"
    implicit_action: str
    template_id: Optional[int] = None
    direction: Optional[str] = None

class TimeRangeEntry(BaseModel):
    type: str
    start_time: Optional[str] = None
    start_date: Optional[str] = None
    end_time: Optional[str] = None
    end_date: Optional[str] = None
    days: Optional[str] = None

class TimeRangePreviewRequest(SwitchTargets):
    name: str
    entries: List[TimeRangeEntry] = Field(..., min_length=1)

class TimeRangeApplyRequest(BaseModel):
    switch_id: int
    name: str
    commands: List[str]

class TimeRangeDeleteRequest(BaseModel):
    switch_id: int
    name: str

class ObjectGroupMemberInput(BaseModel):
    prefix: Optional[str] = None
    group_ref: Optional[str] = None
    protocol: Optional[str] = None
    port: Optional[str] = None

class ObjectGroupCreatePreviewRequest(SwitchTargets):
    name: str
    kind: str  # "address" | "port"
    members: List[ObjectGroupMemberInput] = Field(..., min_length=1)

class ObjectGroupCreateApplyRequest(BaseModel):
    switch_id: int
    name: str
    kind: str
    commands: List[str]

class ObjectGroupMemberAddRequest(BaseModel):
    switch_id: int
    name: str
    kind: str
    member: ObjectGroupMemberInput

class ObjectGroupMemberDeleteRequest(BaseModel):
    switch_id: int
    name: str
    kind: str
    member_line: str

class ObjectGroupMemberEditRequest(BaseModel):
    switch_id: int
    name: str
    kind: str
    original_member: str
    new_member: str

class ObjectGroupDeleteRequest(BaseModel):
    switch_id: int
    name: str
    kind: str


class SaveConfigRequest(SwitchTargets):
    pass

class UndoRequest(BaseModel):
    """Undo a previously applied change on one switch."""
    switch_id: int
    commands: List[str]
    label: str = "change"


# ── logs ──
class LogResponse(BaseModel):
    id: int
    timestamp: datetime
    level: str
    username: str
    message: str
    description: Optional[str]
    undo_commands: Optional[str]  # JSON string of commands
    undo_label: Optional[str]
    switch_id: Optional[int]
    ip_address: Optional[str] = None
    switch_site: Optional[str] = None
    switch_label: Optional[str] = None
    class Config: from_attributes = True

class UndoFromLogRequest(BaseModel):
    log_id: int



class DashboardScanRequest(BaseModel):
    """Which switches to sweep. None or omitted means every owned switch.
    Deliberately not reusing SwitchTargets, whose min_length=1 would make the
    'scan everything' case impossible to express."""
    switch_ids: Optional[List[int]] = None


class MegaVisibleUpdate(BaseModel):
    visible: bool


class SwitchBulkAdd(BaseModel):
    """
    Add one or more switches, optionally on other people's behalf.

    `usernames` is super-admin only; left empty the switches are added for the
    caller, which is the bulk-add path available to everyone.
    """
    ip_addresses: List[str] = Field(..., min_length=1)
    switch_type: str
    site: Optional[str] = None
    ssh_username: Optional[str] = None
    ssh_password: str
    save_password: bool = True
    use_enable: bool = False
    enable_password: Optional[str] = None
    usernames: Optional[List[str]] = None
    access_level: Optional[str] = None
    # Only meaningful alongside write access; read-only never carries a
    # terminal. Left unset it stays on, so a plain write grant is unchanged.
    terminal_access: Optional[bool] = None
    # Add the switches for the caller as well as the named people.
    include_self: bool = False
    # Take over entries another super admin granted. Entries someone added for
    # themselves are never overridden — those are refused whatever this says.
    overwrite_granted: bool = False


class GrantedSwitchUpdate(BaseModel):
    """Edit a switch you granted: its credentials and its privilege."""
    ssh_username: Optional[str] = None
    ssh_password: Optional[str] = None
    use_enable: Optional[bool] = None
    enable_password: Optional[str] = None
    access_level: Optional[str] = None
    terminal_access: Optional[bool] = None


# ── access requests ───────────────────────────────────────────────────────
class AccessRequestCreate(BaseModel):
    """
    Raised from a denied access check, so the fields mirror that form exactly
    -- approving one seeds Add Rule with what was actually asked for.
    """
    switch_id: int
    src_ip: str
    dst_ip: str
    protocol: str = "all"
    port: Optional[str] = None
    icmp_type: Optional[str] = None
    remark: Optional[str] = None
    # Context from the check, so an admin can act without re-running it.
    denied_side: Optional[str] = None
    vlan: Optional[str] = None
    acl_name: Optional[str] = None
    matched_rule: Optional[str] = None
    # A VPC pair is two devices that should agree, so a request for one is
    # usually a request for both -- but each peer gets its own row, because
    # they are applied one at a time.
    include_peer: bool = False


class AccessRequestRemark(BaseModel):
    remark: Optional[str] = None


class AccessRequestResolve(BaseModel):
    """Why it was turned down. Optional when marking one done."""
    note: Optional[str] = None
