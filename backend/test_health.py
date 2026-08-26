"""
The liveness endpoint a service manager or proxy polls.

It has to stay unauthenticated (a health check has no credentials) and it has
to stay quiet (anything that can reach the port can read it). It also has to
fail when the database is unreachable, because a process that answers HTTP
while its database is gone is exactly the process a restart would fix.
"""
import asyncio
import unittest
from unittest.mock import patch

from fastapi import HTTPException

import main


class HealthTests(unittest.TestCase):
    def test_reports_ok(self):
        self.assertEqual(asyncio.run(main.health()), {"status": "ok"})

    def test_says_nothing_but_the_status(self):
        """No version, no counts, no hostname: it is readable without a login."""
        self.assertEqual(list(asyncio.run(main.health())), ["status"])

    def test_takes_no_arguments(self):
        """Nothing injected means nothing to authenticate against, which is
        what lets a service manager call it."""
        import inspect
        self.assertEqual(list(inspect.signature(main.health).parameters), [])

    def test_a_dead_database_is_not_healthy(self):
        class _Dead:
            def execute(self, *a): raise RuntimeError("disk gone")
            def close(self): pass
        with patch.object(main, "SessionLocal", lambda: _Dead()):
            with self.assertRaises(HTTPException) as caught:
                asyncio.run(main.health())
        self.assertEqual(caught.exception.status_code, 503)

    def test_the_session_is_closed_even_when_it_fails(self):
        closed = []
        class _Dead:
            def execute(self, *a): raise RuntimeError("disk gone")
            def close(self): closed.append(True)
        with patch.object(main, "SessionLocal", lambda: _Dead()):
            with self.assertRaises(HTTPException):
                asyncio.run(main.health())
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main(verbosity=2)
