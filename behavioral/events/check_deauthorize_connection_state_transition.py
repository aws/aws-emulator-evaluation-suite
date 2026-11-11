"""deauthorize-connection-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deauthorize-connection-state-transition"
GROUP = 'connection'
SERVICES = ['events']

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise

def _wait_connection(ev, name, states, timeout_s):
    _deadline = time.monotonic() + timeout_s
    d = ev.describe_connection(Name=name)
    while time.monotonic() < _deadline:
        d = ev.describe_connection(Name=name)
        if d["ConnectionState"] in states:
            break
        time.sleep(1)
    return d

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeauthorizeConnection drives an AUTHORIZED connection to DEAUTHORIZED."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    ev.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda n=name: _cleanup_connection(ev, n))

    # Both the AUTHORIZED and DEAUTHORIZED settles are asynchronous, hence the bounded waits.
    _wait_connection(ev, name, ("AUTHORIZED", "CREATE_FAILED"), 60)

    ev.deauthorize_connection(Name=name)
    desc = _wait_connection(ev, name, ("DEAUTHORIZED",), 90)
    assert desc["ConnectionState"] == "DEAUTHORIZED", (
        f"expected DEAUTHORIZED, got {desc['ConnectionState']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
