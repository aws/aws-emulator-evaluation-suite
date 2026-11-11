"""update-connection-authorization-type."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-connection-authorization-type"
GROUP = 'connection'
SERVICES = ['events']

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise

def _wait_connection(ev, name, predicate, timeout_s):
    _deadline = time.monotonic() + timeout_s
    d = ev.describe_connection(Name=name)
    while time.monotonic() < _deadline:
        d = ev.describe_connection(Name=name)
        if predicate(d):
            break
        time.sleep(1)
    return d

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateConnection switches AuthorizationType from API_KEY to BASIC in place; the connection
    returns to AUTHORIZED with the same ConnectionArn."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-conn-")
    created = ev.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda n=name: _cleanup_connection(ev, n))

    # Connection authorization settles asynchronously.
    _wait_connection(ev, name, lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"), 60)

    ev.update_connection(
        Name=name,
        AuthorizationType="BASIC",
        AuthParameters={
            "BasicAuthParameters": {"Username": "user1", "Password": "pass-1234"}
        },
    )

    desc = _wait_connection(
        ev,
        name,
        lambda d: d["ConnectionState"] in ("AUTHORIZED", "UPDATE_FAILED")
        and d["AuthorizationType"] == "BASIC",
        90,
    )
    assert desc["ConnectionState"] == "AUTHORIZED", f"expected AUTHORIZED, got {desc}"
    assert desc["AuthorizationType"] == "BASIC", f"auth type not updated: {desc}"
    assert desc["ConnectionArn"] == created["ConnectionArn"], "ConnectionArn must be stable"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
