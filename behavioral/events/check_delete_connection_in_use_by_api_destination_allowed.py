"""delete-connection-in-use-by-api-destination-allowed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-connection-in-use-by-api-destination-allowed"
GROUP = 'api-destination'
SERVICES = ['events']

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise

def _cleanup_api_destination(ev, name):
    try:
        ev.delete_api_destination(Name=name)
    except ClientError as exc:
        if "NotFound" not in exc.response["Error"]["Code"]:
            raise

def _wait(ev, describe, predicate, timeout_s):
    _deadline = time.monotonic() + timeout_s
    d = describe()
    while time.monotonic() < _deadline:
        d = describe()
        if predicate(d):
            break
        time.sleep(1)
    return d

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EventBridge does not reference-count connections: deleting one an API destination uses
    succeeds, and the destination stays ACTIVE with its now-dangling ConnectionArn."""
    ev = ctx.client("events")
    conn_name = ctx.unique_name("sim2real-behav-conn-")
    conn = ev.create_connection(
        Name=conn_name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda n=conn_name: _cleanup_connection(ev, n))
    _wait(ev, lambda: ev.describe_connection(Name=conn_name),
          lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"), 60)

    dest_name = ctx.unique_name("sim2real-behav-apidest-")
    ev.create_api_destination(
        Name=dest_name,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint="https://example.com/webhook",
        HttpMethod="POST",
    )
    ctx.on_cleanup(lambda n=dest_name: _cleanup_api_destination(ev, n))
    _wait(ev, lambda: ev.describe_api_destination(Name=dest_name),
          lambda d: d["ApiDestinationState"] == "ACTIVE", 60)

    ev.delete_connection(Name=conn_name)

    still = ev.describe_api_destination(Name=dest_name)
    assert still["ConnectionArn"] == conn["ConnectionArn"], (
        f"API destination must keep its (now dangling) ConnectionArn: {still}"
    )
    assert still["ApiDestinationState"] == "ACTIVE", (
        f"API destination should stay ACTIVE even though its connection was just "
        f"deleted from under it (real EventBridge does not revoke on dangling ref): {still}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
