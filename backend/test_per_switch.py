"""
The two per-switch runners, and why they are not interchangeable.

/api/write/rule-preview called _per_switch after it had been deleted, so Add
ACL Rule answered 500 for every request. The regression test is cheap: assert
both helpers exist and behave, since the call sites choose between them by
name and a missing one is only found at runtime.
"""
import asyncio
import unittest

import main
import ssh_manager
from validators import ValidationError


class _T:
    def __init__(self, i):
        self.id, self.label, self.ip = i, f"sw-{i}", f"10.0.0.{i}"
        self.type, self.is_nexus = "nexus", True


class PerSwitchTests(unittest.TestCase):
    def test_both_runners_exist(self):
        """The 500 was a NameError: one of these had been removed while a
        call site still named it."""
        self.assertTrue(callable(main._per_switch))
        self.assertTrue(callable(main._per_switch_async))

    def test_sync_runner_returns_one_entry_per_switch(self):
        out = main._per_switch([_T(1), _T(2)], lambda t: {"ok": t.id})
        self.assertEqual([e["switch_id"] for e in out], [1, 2])
        self.assertEqual([e["switch_name"] for e in out], ["sw-1", "sw-2"])
        self.assertEqual([e["ok"] for e in out], [1, 2])
        self.assertTrue(all(e["error"] is None for e in out))

    def test_a_switch_error_is_captured_not_raised(self):
        def boom(t):
            if t.id == 1:
                raise ssh_manager.SSHError("unreachable")
            return {"ok": True}
        out = main._per_switch([_T(1), _T(2)], boom)
        self.assertEqual(out[0]["error"], "unreachable")
        self.assertIsNone(out[1]["error"])

    def test_a_validation_error_is_captured_too(self):
        out = main._per_switch([_T(1)], lambda t: (_ for _ in ()).throw(
            ValidationError("bad input")))
        self.assertEqual(out[0]["error"], "bad input")

    def test_the_two_agree_on_shape(self):
        sync = main._per_switch([_T(1)], lambda t: {"v": 1})
        # asyncio.run rather than get_event_loop(): by the time this runs,
        # another test module may already have closed the loop it created.
        agen = asyncio.run(main._per_switch_async([_T(1)], lambda t: {"v": 1}))
        self.assertEqual(set(sync[0]), set(agen[0]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
