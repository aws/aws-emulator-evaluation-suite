"""create-connection-state-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-connection-state-transition"
GROUP = 'connection'
SERVICES = ['events']

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateConnection settles into AUTHORIZED after the transient CREATING/AUTHORIZING states,
    and DescribeConnection reflects it."""
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

    desc = ev.describe_connection(Name=name)
    assert desc["ConnectionState"] in ("CREATING", "AUTHORIZING", "AUTHORIZED"), (
        f"unexpected initial ConnectionState: {desc.get('ConnectionState')}"
    )

    # The AUTHORIZED settle is asynchronous, so poll to a bounded deadline.
    _deadline = time.monotonic() + 60
    while time.monotonic() < _deadline:
        desc = ev.describe_connection(Name=name)
        if desc["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"):
            break
        time.sleep(1)
    assert desc["ConnectionState"] == "AUTHORIZED", (
        f"expected AUTHORIZED, got {desc['ConnectionState']} ({desc.get('StateReason')})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
