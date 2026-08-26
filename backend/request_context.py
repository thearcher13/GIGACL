"""
The address the current request came from, for code too deep to be handed the
Request object.

Audit rows and presence tracking both want to record who connected from where,
but they are written from helpers several layers below the endpoint. Threading
a `client_ip` argument through every one of those call sites would touch most
of the app to carry one value, so the middleware in main.py parks it here for
the duration of the request instead.

A ContextVar, not a global: FastAPI serves requests concurrently on one thread,
and a plain module variable would let one request's address leak into another's
log entries.
"""
from contextvars import ContextVar
from typing import Optional

_client_ip: ContextVar[Optional[str]] = ContextVar("client_ip", default=None)


def set_client_ip(ip: Optional[str]):
    """Bind the address for this request. Returns a token to reset with."""
    return _client_ip.set(ip)


def reset_client_ip(token) -> None:
    _client_ip.reset(token)


def client_ip() -> Optional[str]:
    """The current request's address, or None outside a request."""
    return _client_ip.get()
