"""While a test runs, refuse every host name lookup the emulator does not serve.

``Context.client`` already refuses an SDK request to such a host (``before-send``). A test that
dials a URL itself (``urllib``, ``http.client``, ``requests``) resolves its host first, and this
refuses that lookup with ``CapabilityNotOffered``: the test fails and nothing leaves this machine.
A host passes when it is local (``target.is_local_host`` with the run's own hosts) and is not a
name under an IP literal. Only this process is guarded; a CLI or tool subprocess is not.
"""

import sys
import threading
from collections.abc import Iterable, Iterator
from contextlib import contextmanager

from fidelity_tests_runner.context import CapabilityNotOffered
from fidelity_tests_runner.published import name_under_ip
from fidelity_tests_runner.target import is_local_host

#: Audit events that resolve a host; the host is the first argument of each.
LOOKUP_EVENTS = frozenset({"socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex"})

_lock = threading.Lock()
_installed = False
_active: dict = {"endpoint": None, "own": ()}


def permits(host: str, endpoint: str, own_hosts: Iterable[str] = ()) -> bool:
    """Whether a test run against ``endpoint`` may resolve ``host``."""
    return bool(host) and not name_under_ip(host) and is_local_host(host, endpoint, own_hosts)


def _hook(event: str, args: tuple) -> None:
    endpoint = _active["endpoint"]
    if endpoint is None or event not in LOOKUP_EVENTS or not args:
        return
    host = args[0]
    if host is None:  # a wildcard bind, not a lookup
        return
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    if not permits(str(host), endpoint, _active["own"]):
        raise CapabilityNotOffered(f"the emulator serves no address for {host}")


@contextmanager
def guarding(endpoint: str, own_hosts: Iterable[str] = ()) -> Iterator[None]:
    """Refuse lookups of hosts the emulator does not serve until the block ends."""
    global _installed
    with _lock:
        if not _installed:
            sys.addaudithook(_hook)  # an audit hook cannot be removed; it is idle when inactive
            _installed = True
        saved = dict(_active)
        _active.update(endpoint=endpoint, own=tuple(own_hosts))
    try:
        yield
    finally:
        with _lock:
            _active.update(saved)
