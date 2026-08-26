import asyncio
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from auth import require_admin
from database import User, ROLE_ADMIN, ROLE_USER
import main
import ssh_manager
from ssh_manager import SSHSession
import terminal_service


def target(switch_id, peer_id=None, switch_type="nexus"):
    switch = SimpleNamespace(vpc_peer_id=peer_id)
    return SimpleNamespace(
        id=switch_id,
        label=f"switch-{switch_id}",
        ip=f"10.0.0.{switch_id}",
        type=switch_type,
        ssh_username="operator",
        password="secret",
        use_enable=False,
        enable_password=None,
        sw=switch,
    )


class TerminalWorkspaceTests(unittest.TestCase):
    def setUp(self):
        terminal_service.reset_for_tests()

    def tearDown(self):
        terminal_service.reset_for_tests()

    def test_up_to_three_distinct_switches_per_user(self):
        first = terminal_service.reserve("admin", [target(1)])
        second = terminal_service.reserve("admin", [target(2)])
        third = terminal_service.reserve("admin", [target(3)])
        with self.assertRaises(HTTPException) as raised:
            terminal_service.reserve("admin", [target(4)])
        self.assertEqual(raised.exception.status_code, 409)
        terminal_service.release(first)
        terminal_service.release(second)
        terminal_service.release(third)

    def test_same_switch_cannot_be_opened_twice(self):
        first = terminal_service.reserve("admin", [target(1)])
        with self.assertRaisesRegex(HTTPException, "already open"):
            terminal_service.reserve("admin", [target(1)])
        terminal_service.release(first)

    def test_vpc_pair_leaves_room_for_one_other_switch(self):
        pair = terminal_service.reserve(
            "admin", [target(1, peer_id=2), target(2, peer_id=1)])
        extra = terminal_service.reserve("admin", [target(3)])
        with self.assertRaises(HTTPException) as raised:
            terminal_service.reserve("admin", [target(4)])
        self.assertEqual(raised.exception.status_code, 409)
        terminal_service.release(pair)
        terminal_service.release(extra)

    def test_two_terminals_require_reciprocal_vpc_pair(self):
        with self.assertRaises(HTTPException) as raised:
            terminal_service.reserve(
                "admin", [target(1, peer_id=2), target(2, peer_id=99)])
        self.assertEqual(raised.exception.status_code, 400)

        workspace = terminal_service.reserve(
            "admin", [target(1, peer_id=2), target(2, peer_id=1)])
        self.assertEqual(len(workspace.targets), 2)

        with self.assertRaises(HTTPException):
            terminal_service.reserve(
                "other-admin", [target(3, peer_id=4, switch_type="ios"),
                                target(4, peer_id=3, switch_type="ios")])

    def test_config_mode_entry_failure_reconnects_and_retries_once(self):
        stale = SimpleNamespace(send_config_commands=unittest.mock.Mock(
            side_effect=ssh_manager.SSHError(
                "Configuration failed on 10.0.0.1: Failed to enter configuration mode.")))
        fresh = SimpleNamespace(send_config_commands=unittest.mock.Mock(
            return_value="configuration applied"))
        with patch.object(ssh_manager, "get_or_create_session",
                          side_effect=[stale, fresh]) as get_session, \
             patch.object(ssh_manager, "invalidate_session") as invalidate:
            output = ssh_manager.run_config(
                "operator", "10.0.0.1", "secret", ["interface Vlan10"])

        self.assertEqual(output, "configuration applied")
        self.assertEqual(get_session.call_count, 2)
        invalidate.assert_called_once_with("operator", "10.0.0.1")

    def test_workspace_token_can_only_be_claimed_once(self):
        workspace = terminal_service.reserve("admin", [target(1)])
        self.assertIs(terminal_service.claim(workspace.id), workspace)
        self.assertIsNone(terminal_service.claim(workspace.id))
        self.assertTrue(terminal_service.close_owned(workspace.id, "admin"))

    def test_only_owner_can_close_workspace(self):
        workspace = terminal_service.reserve("admin", [target(1)])
        self.assertFalse(terminal_service.close_owned(workspace.id, "someone-else"))
        self.assertTrue(terminal_service.close_owned(workspace.id, "admin"))
        self.assertFalse(terminal_service.close_owned(workspace.id, "admin"))

    def test_user_role_cannot_access_admin_terminal_routes(self):
        regular_user = User(username="viewer", hashed_password="x", role=ROLE_USER)
        with self.assertRaises(HTTPException) as raised:
            asyncio.run(require_admin(regular_user))
        self.assertEqual(raised.exception.status_code, 403)

        administrator = User(username="operator", hashed_password="x", role=ROLE_ADMIN)
        self.assertIs(asyncio.run(require_admin(administrator)), administrator)

    def test_interactive_shell_exit_is_detected(self):
        session = SSHSession("10.0.0.1", "operator", "secret")
        channel = SimpleNamespace(
            closed=False, eof_received=False, exit_status_ready=lambda: False)
        session._conn = SimpleNamespace(remote_conn=channel)
        session.is_alive = lambda: True
        self.assertTrue(session.is_interactive_alive())

        channel.eof_received = True
        self.assertFalse(session.is_interactive_alive())

    def test_interactive_connection_preserves_raw_terminal_control_codes(self):
        class Connection:
            ansi_escape_codes = True
            disable_lf_normalization = False
            established_with = None

            def establish_connection(self, width, height):
                self.established_with = (width, height)

            def _test_channel_read(self, pattern):
                self.prompt_pattern = pattern

            def set_base_prompt(self):
                self.base_prompt_ready = True

            def send_command(self, command, read_timeout=0):
                return ""

            def find_prompt(self):
                return "switch#"

        interactive_connection = Connection()
        with patch("ssh_manager.ConnectHandler", return_value=interactive_connection):
            SSHSession("10.0.0.1", "operator", "secret",
                       switch_type="nexus", interactive=True).connect()
        self.assertFalse(interactive_connection.ansi_escape_codes)
        self.assertTrue(interactive_connection.disable_lf_normalization)
        self.assertEqual(interactive_connection.established_with, (80, 34))
        self.assertEqual(interactive_connection.prompt_pattern, r"[>#]")
        self.assertTrue(interactive_connection.base_prompt_ready)

        automated_connection = Connection()
        with patch("ssh_manager.ConnectHandler", return_value=automated_connection):
            SSHSession("10.0.0.1", "operator", "secret",
                       switch_type="nexus").connect()
        self.assertTrue(automated_connection.ansi_escape_codes)
        self.assertFalse(automated_connection.disable_lf_normalization)

        class EnableConnection(Connection):
            def __init__(self):
                self.events = []

            def establish_connection(self, width, height):
                self.events.append("established")

            def _test_channel_read(self, pattern):
                self.events.append("prompt-ready")

            def set_base_prompt(self):
                self.events.append("base-prompt-set")

            def enable(self):
                self.events.append("enabled")

        enable_connection = EnableConnection()
        with patch("ssh_manager.ConnectHandler", return_value=enable_connection):
            SSHSession("10.0.0.1", "operator", "secret", switch_type="ios",
                       use_enable=True, enable_password="enable-secret",
                       interactive=True).connect()
        self.assertEqual(enable_connection.events,
                         ["established", "prompt-ready", "base-prompt-set", "enabled"])

    def test_websocket_input_and_resize_reach_selected_terminal(self):
        class Socket:
            def __init__(self):
                self.messages = iter([
                    {"type": "input", "terminal": 0, "data": "show clock\r"},
                    {"type": "resize", "terminal": 0, "cols": 120, "rows": 40},
                    {"type": "close"},
                ])

            async def receive_json(self):
                return next(self.messages)

        class Connection:
            def __init__(self):
                self.input = []
                self.sizes = []

            def write_channel(self, data):
                self.input.append(data)

            def resize_terminal(self, columns, rows):
                self.sizes.append((columns, rows))

        connection = Connection()
        asyncio.run(main._terminal_input_loop(Socket(), {0: connection}))
        self.assertEqual(connection.input, ["show clock\r"])
        self.assertEqual(connection.sizes, [(120, 40)])

    def test_output_pump_reports_output_and_shell_disconnect(self):
        class Socket:
            def __init__(self):
                self.sent = []

            async def send_json(self, message):
                self.sent.append(message)

        class Connection:
            def __init__(self):
                self.reads = iter(["switch#", ""])

            def read_channel(self):
                return next(self.reads)

            def is_interactive_alive(self):
                return False

        socket = Socket()
        asyncio.run(main._terminal_output_pump(
            socket, asyncio.Lock(), 0, Connection()))
        self.assertEqual(socket.sent[0]["data"], "switch#")
        self.assertEqual(socket.sent[-1]["status"], "disconnected")


if __name__ == "__main__":
    unittest.main()
