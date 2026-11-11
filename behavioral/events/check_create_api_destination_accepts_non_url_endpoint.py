"""create-api-destination-accepts-non-url-endpoint."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-destination-accepts-non-url-endpoint"
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
            return d
        time.sleep(1)
    raise TimeoutError(f"condition not met within {timeout_s}s: last={d}")

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EventBridge does not validate that InvocationEndpoint is a URL: CreateApiDestination with a
    bare string is accepted, becomes ACTIVE, and stores the endpoint verbatim."""
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
    created = ev.create_api_destination(
        Name=dest_name,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint="not-a-url",
        HttpMethod="POST",
    )
    ctx.on_cleanup(lambda n=dest_name: _cleanup_api_destination(ev, n))
    assert created["ApiDestinationState"] in ("ACTIVE", "INACTIVE"), f"unexpected state: {created}"

    _wait(ev, lambda: ev.describe_api_destination(Name=dest_name),
          lambda d: d["ApiDestinationState"] == "ACTIVE", 60)

    desc = ev.describe_api_destination(Name=dest_name)
    assert desc["InvocationEndpoint"] == "not-a-url", (
        f"endpoint must be stored verbatim, got {desc['InvocationEndpoint']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
