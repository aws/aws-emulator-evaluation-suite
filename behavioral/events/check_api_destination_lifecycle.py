"""api-destination-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-destination-lifecycle"
GROUP = 'api-destination'
SERVICES = ['events']

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")

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
    """Poll describe() until predicate holds; raise on timeout, never return the stale value."""
    _deadline = time.monotonic() + timeout_s
    d = describe()
    while time.monotonic() < _deadline:
        d = describe()
        if predicate(d):
            return d
        time.sleep(1)
    raise AssertionError(f"condition not met within {timeout_s}s; last read {d!r}")

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An API destination on a real connection settles ACTIVE and is listable and describable;
    UpdateApiDestination mutates it in place and DeleteApiDestination makes it disappear.
    The connection AUTHORIZED and destination ACTIVE settles are asynchronous, so both are polled."""
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
    authorized = _wait(ev, lambda: ev.describe_connection(Name=conn_name),
                        lambda d: d["ConnectionState"] in ("AUTHORIZED", "CREATE_FAILED"), 60)
    assert authorized["ConnectionState"] == "AUTHORIZED", (
        f"the API_KEY connection must settle AUTHORIZED, got {authorized['ConnectionState']!r} "
        f"StateReason={authorized.get('StateReason')!r}"
    )

    dest_name = ctx.unique_name("sim2real-behav-apidest-")
    created = ev.create_api_destination(
        Name=dest_name,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint="https://example.com/webhook",
        HttpMethod="POST",
        InvocationRateLimitPerSecond=10,
    )
    ctx.on_cleanup(lambda n=dest_name: _cleanup_api_destination(ev, n))
    assert created["ApiDestinationState"] in ("ACTIVE", "INACTIVE"), f"unexpected state: {created}"

    _wait(ev, lambda: ev.describe_api_destination(Name=dest_name),
          lambda d: d["ApiDestinationState"] == "ACTIVE", 60)

    desc = ev.describe_api_destination(Name=dest_name)
    assert desc["ApiDestinationState"] == "ACTIVE", (
        f"the api destination must settle ACTIVE, got {desc['ApiDestinationState']!r}"
    )
    assert desc["HttpMethod"] == "POST", f"expected HttpMethod POST, got {desc['HttpMethod']}"
    assert desc["InvocationRateLimitPerSecond"] == 10, (
        f"expected InvocationRateLimitPerSecond 10, got {desc['InvocationRateLimitPerSecond']}"
    )
    assert desc["ConnectionArn"] == conn["ConnectionArn"], (
        f"expected ConnectionArn {conn['ConnectionArn']}, got {desc['ConnectionArn']}"
    )

    listed = {d["Name"] for d in ev.list_api_destinations(NamePrefix=dest_name)["ApiDestinations"]}
    assert listed == {dest_name}, f"NamePrefix filter broken: {listed}"

    ev.update_api_destination(Name=dest_name, HttpMethod="PUT", InvocationRateLimitPerSecond=5)
    _wait(ev, lambda: ev.describe_api_destination(Name=dest_name),
          lambda d: d["HttpMethod"] == "PUT", 60)
    updated = ev.describe_api_destination(Name=dest_name)
    assert updated["HttpMethod"] == "PUT", f"http method not updated: {updated}"
    assert updated["InvocationRateLimitPerSecond"] == 5, f"rate limit not updated: {updated}"
    assert updated["ApiDestinationArn"] == created["ApiDestinationArn"], "ARN must be stable"

    ev.delete_api_destination(Name=dest_name)
    err = _error(lambda: ev.describe_api_destination(Name=dest_name))
    expected = (
        "ResourceNotFoundException",
        f"Failed to describe the api-destination(s). An api-destination '{dest_name}' does not exist.",
    )
    assert err == expected, f"expected {expected}, got {err}"

    err = _error(
        lambda: ev.update_api_destination(Name=dest_name, HttpMethod="GET")
    )
    expected = (
        "ResourceNotFoundException",
        f"Failed to update the api-destination(s). An api-destination '{dest_name}' does not exist.",
    )
    assert err == expected, (
        f"a mutation on the deleted destination must also fail not-found with {expected}, got {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
