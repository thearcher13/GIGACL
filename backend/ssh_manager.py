"""
SSH connection manager built on Netmiko.
Netmiko handles legacy Cisco algorithm negotiation, enable mode,
paging and prompt detection.
"""
import re
import threading
import logging
from typing import Optional, Dict, Tuple, List

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    NetmikoBaseException,
)
from paramiko.ssh_exception import SSHException

from config import settings

log = logging.getLogger(__name__)

_sessions: Dict[Tuple[str, str], "SSHSession"] = {}
_lock = threading.Lock()

DEVICE_TYPE_MAP = {
    "ios":   "cisco_ios",
    "nexus": "cisco_nxos",
    "nxos":  "cisco_nxos",
    "iosxe": "cisco_xe",
    "iosxr": "cisco_xr",
}

# Patterns that indicate the switch rejected a command
ERROR_PATTERNS = [
    (r"%\s*Invalid input", "The switch rejected the command syntax."),
    (r"%\s*Incomplete command", "The command was incomplete."),
    (r"%\s*Ambiguous command", "The command was ambiguous."),
    (r"%\s*Unrecognized command", "The switch did not recognise the command."),
    (r"%\s*Access denied", "Access denied by the switch."),
    (r"%\s*Permission denied", "Permission denied by the switch."),
    (r"%\s*Authorization failed", "Command authorization failed on the switch."),
    (r"ERROR:", "The switch returned an error."),
    (r"%\s*Error", "The switch returned an error."),
    (r"Invalid command", "Invalid command."),
    (r"Command rejected", "The switch rejected the command."),
    (r"%.*object[- ]group.*(?:not found|does not exist|type)",
     "The switch rejected the object-group reference."),
    (r"%.*(?:failed|failure|cannot|can't)",
     "The switch reported that the command failed."),
]


class SSHError(Exception):
    """Raised for any SSH / switch communication problem."""
    pass


def detect_switch_error(output: str) -> Optional[str]:
    """
    Inspect raw switch output. Return a human message if it looks like
    an error, otherwise None.
    """
    if not output:
        return None
    for pattern, message in ERROR_PATTERNS:
        if re.search(pattern, output, re.IGNORECASE):
            return message
    # Cisco marks the offending token with ^ under the command
    if re.search(r"^\s*\^\s*$", output, re.MULTILINE) and "%" in output:
        return "The switch rejected the command syntax."
    return None


class SSHSession:
    def __init__(self, ip: str, username: str, password: str,
                 switch_type: str = "ios", use_enable: bool = False,
                 enable_password: Optional[str] = None,
                 interactive: bool = False):
        self.ip = ip
        self.username = username
        self.password = password
        self.switch_type = (switch_type or "ios").lower()
        self.use_enable = use_enable
        self.enable_password = enable_password  # Must be provided if use_enable=True
        self.interactive = interactive
        self._conn: Optional[ConnectHandler] = None
        self._cmd_lock = threading.Lock()

    # ── connection ──
    def _device(self) -> dict:
        d = {
            "device_type":    DEVICE_TYPE_MAP.get(self.switch_type, "cisco_ios"),
            "host":           self.ip,
            "username":       self.username,
            "password":       self.password,
            "timeout":        25,
            "conn_timeout":   20,
            "auth_timeout":   20,
            "banner_timeout": 20,
            "fast_cli":       False,
        }
        if self.use_enable:
            if not self.enable_password:
                raise SSHError(
                    f"Enable password is required for {self.ip} but was not provided."
                )
            d["secret"] = self.enable_password
        return d

    def connect(self) -> str:
        try:
            device = self._device()
            if self.interactive:
                # Authenticate and open a VT100 shell without Netmiko's
                # automation session_preparation. That preparation sends
                # terminal length/width commands which pollute CLI history.
                device["auto_connect"] = False
                conn = ConnectHandler(**device)
                conn.establish_connection(width=80, height=34)
                # Synchronize with the initial prompt before checking or
                # entering enable mode. This sends no CLI setup commands.
                conn._test_channel_read(pattern=r"[>#]")
                conn.set_base_prompt()
            else:
                conn = ConnectHandler(**device)
        except NetmikoAuthenticationException:
            raise SSHError(
                f"Authentication failed on {self.ip}. The username "
                f"'{self.username}' or the SSH password is incorrect."
            )
        except NetmikoTimeoutException:
            raise SSHError(
                f"Timed out connecting to {self.ip}. Check the IP address, "
                f"routing, and that SSH is enabled on the switch."
            )
        except SSHException as e:
            raise SSHError(
                f"SSH negotiation with {self.ip} failed ({e}). The switch may "
                f"only support older ciphers or key exchange methods."
            )
        except NetmikoBaseException as e:
            raise SSHError(f"Could not connect to {self.ip}: {e}")
        except SSHError:
            raise
        except Exception as e:
            raise SSHError(f"Unexpected error connecting to {self.ip}: {e}")

        if self.use_enable:
            try:
                conn.enable()
            except Exception:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                raise SSHError(
                    f"Could not enter enable mode on {self.ip}. "
                    f"The enable password was rejected."
                )

        self._conn = conn
        try:
            prompt = conn.find_prompt()
        except Exception:
            prompt = ""

        if self.interactive:
            # NX-OS enables Netmiko's ANSI stripping and all Netmiko drivers
            # normalize carriage returns for command parsing. A real terminal
            # needs both byte streams intact for cursor movement, history, and
            # backspace redraws to work correctly in xterm.
            conn.ansi_escape_codes = False
            conn.disable_lf_normalization = True

        return prompt

    # ── commands ──
    def send_command(self, command: str, timeout: float = 30) -> str:
        with self._cmd_lock:
            if self._conn is None:
                raise SSHError(f"Not connected to {self.ip}.")
            try:
                return self._conn.send_command(command, read_timeout=timeout)
            except NetmikoTimeoutException:
                raise SSHError(
                    f"'{command}' timed out on {self.ip} after {timeout:.0f}s."
                )
            except Exception as e:
                raise SSHError(f"'{command}' failed on {self.ip}: {e}")

    def send_config_commands(self, commands: List[str], timeout: float = 30) -> str:
        with self._cmd_lock:
            if self._conn is None:
                raise SSHError(f"Not connected to {self.ip}.")
            try:
                return self._conn.send_config_set(commands, read_timeout=timeout)
            except NetmikoTimeoutException:
                raise SSHError(f"Configuration commands timed out on {self.ip}.")
            except Exception as e:
                raise SSHError(f"Configuration failed on {self.ip}: {e}")

    def send_command_with_confirm(self, command: str, timeout: float = 60) -> str:
        """
        Send a command that requires confirmation (like copy commands).
        Uses send_command_timing which doesn't wait for a specific prompt.
        """
        with self._cmd_lock:
            if self._conn is None:
                raise SSHError(f"Not connected to {self.ip}.")
            try:
                # Send the command and wait for any output (doesn't expect prompt)
                out = self._conn.send_command_timing(command, read_timeout=timeout)
                # If there's a prompt (like "Destination filename"), send Enter
                if re.search(r"\[.*\]\?|confirm", out, re.IGNORECASE):
                    out += self._conn.send_command_timing("", read_timeout=timeout)
                return out
            except NetmikoTimeoutException:
                raise SSHError(
                    f"'{command}' timed out on {self.ip} after {timeout:.0f}s."
                )
            except Exception as e:
                raise SSHError(f"'{command}' failed on {self.ip}: {e}")

    # ── interactive terminal I/O ──
    def read_channel(self) -> str:
        if self._conn is None:
            return ""
        try:
            return self._conn.read_channel()
        except Exception as e:
            raise SSHError(f"Terminal read failed on {self.ip}: {e}")

    def write_channel(self, data: str):
        if self._conn is None:
            raise SSHError(f"Not connected to {self.ip}.")
        try:
            self._conn.write_channel(data)
        except Exception as e:
            raise SSHError(f"Terminal write failed on {self.ip}: {e}")

    def resize_terminal(self, columns: int, rows: int):
        if self._conn is None:
            return
        try:
            channel = getattr(self._conn, "remote_conn", None)
            if channel and hasattr(channel, "resize_pty"):
                channel.resize_pty(width=columns, height=rows)
        except Exception:
            # Some older Cisco SSH implementations do not support PTY resize.
            pass

    def is_interactive_alive(self) -> bool:
        """Check shell/channel state without writing probe bytes to the switch."""
        if self._conn is None:
            return False
        channel = getattr(self._conn, "remote_conn", None)
        try:
            if channel is None or (
                getattr(channel, "closed", False) or
                getattr(channel, "eof_received", False) or
                (hasattr(channel, "exit_status_ready") and
                 channel.exit_status_ready())
            ):
                return False
            transport = getattr(channel, "transport", None)
            if transport is not None and hasattr(transport, "is_active"):
                return bool(transport.is_active())
            return True
        except Exception:
            return False

    # ── lifecycle ──
    def is_alive(self) -> bool:
        try:
            return self._conn is not None and self._conn.is_alive()
        except Exception:
            return False

    def disconnect(self):
        try:
            if self._conn:
                self._conn.disconnect()
        except Exception:
            pass
        self._conn = None


# ── session cache ──

def get_or_create_session(username: str, switch_ip: str, ssh_password: str,
                          switch_type: str = "ios",
                          use_enable: bool = False,
                          enable_password: Optional[str] = None) -> SSHSession:
    key = (username, switch_ip)
    with _lock:
        s = _sessions.get(key)
        if s and s.is_alive():
            return s
        if s:
            s.disconnect()
        s = SSHSession(switch_ip, username, ssh_password, switch_type, 
                      use_enable, enable_password)
        s.connect()
        _sessions[key] = s
        return s


def has_session(username: str, switch_ip: str) -> bool:
    """Whether a session is already cached for this pair.

    Sessions are never evicted, so a sweep that opens one on every switch
    would leave a connection and a VTY line held on each device for the life
    of the process. Callers check this first so they can hand back anything
    they opened themselves and leave the cache as they found it.
    """
    with _lock:
        return (username, switch_ip) in _sessions


def invalidate_session(username: str, switch_ip: str):
    with _lock:
        s = _sessions.pop((username, switch_ip), None)
    if s:
        s.disconnect()


def run_command(username: str, switch_ip: str, ssh_password: str, command: str,
                switch_type: str = "ios", timeout: float = 30,
                use_enable: bool = False, enable_password: Optional[str] = None) -> str:
    s = get_or_create_session(username, switch_ip, ssh_password,
                              switch_type, use_enable, enable_password)
    return s.send_command(command, timeout=timeout)


def run_command_with_confirm(username: str, switch_ip: str, ssh_password: str, command: str,
                              switch_type: str = "ios", timeout: float = 60,
                              use_enable: bool = False, enable_password: Optional[str] = None) -> str:
    """Run a command that requires confirmation (like copy running-config startup-config)."""
    s = get_or_create_session(username, switch_ip, ssh_password,
                              switch_type, use_enable, enable_password)
    return s.send_command_with_confirm(command, timeout=timeout)


def run_config(username: str, switch_ip: str, ssh_password: str,
               commands: List[str], switch_type: str = "ios",
               use_enable: bool = False, enable_password: Optional[str] = None,
               timeout: float = 30) -> str:
    s = get_or_create_session(username, switch_ip, ssh_password,
                              switch_type, use_enable, enable_password)
    try:
        return s.send_config_commands(commands, timeout=timeout)
    except SSHError as exc:
        # A long-lived Netmiko channel can occasionally retain a stale prompt
        # and fail before sending any configuration command. Reconnecting is
        # safe for this specific pre-command failure and avoids making users
        # repeat Undo or Apply manually.
        if "failed to enter configuration mode" not in str(exc).lower():
            raise
        invalidate_session(username, switch_ip)
        fresh = get_or_create_session(
            username, switch_ip, ssh_password, switch_type,
            use_enable, enable_password)
        return fresh.send_config_commands(commands, timeout=timeout)


def fetch_hostname(username: str, switch_ip: str, ssh_password: str,
                   switch_type: str = "ios", use_enable: bool = False,
                   enable_password: Optional[str] = None) -> str:
    key = (username, switch_ip)
    with _lock:
        old = _sessions.pop(key, None)
    if old:
        old.disconnect()

    s = SSHSession(switch_ip, username, ssh_password, switch_type, 
                  use_enable, enable_password)
    prompt = s.connect()
    with _lock:
        _sessions[key] = s

    try:
        out = s.send_command("show running-config | include ^hostname", timeout=15)
        m = re.search(r"hostname\s+(\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass

    if prompt:
        m = re.search(r"([A-Za-z0-9_\-\.]+)\s*[#>]", prompt)
        if m:
            return m.group(1)
    return switch_ip
