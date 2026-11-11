"""create-api-destination-requires-existing-connection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-api-destination-requires-existing-connection"
GROUP = 'api-destination'
SERVICES = ['events']

def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
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
    _deadline = time.monotonic() + timeout_s
    d = describe()
    while time.monotonic() < _deadline:
        d = describe()
        if predicate(d):
            break
        time.sleep(1)
    return d

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiDestination with a ConnectionArn naming no existing connection fails with
    ResourceNotFoundException and creates nothing; the call succeeds against a real connection."""
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

    # Positive control: CreateApiDestination against a real connection succeeds.
    good_name = ctx.unique_name("sim2real-behav-apidest-good-")
    created = ev.create_api_destination(
        Name=good_name,
        ConnectionArn=conn["ConnectionArn"],
        InvocationEndpoint="https://example.com/webhook",
        HttpMethod="POST",
    )
    ctx.on_cleanup(lambda n=good_name: _cleanup_api_destination(ev, n))
    assert created["ApiDestinationState"] in ("ACTIVE", "INACTIVE"), f"unexpected state: {created}"

    # Build a well-formed but non-existent connection ARN in THIS account/region
    # so the failure is genuinely "not found" rather than a cross-account issue.
    bogus_conn_arn = conn["ConnectionArn"].rsplit(":connection/", 1)[0] + (
        f":connection/{ctx.unique_name('sim2real-behav-no-conn-')}/"
        "00000000-0000-0000-0000-000000000000"
    )

    bad_name = ctx.unique_name("sim2real-behav-apidest-bad-")
    err = _error(
        lambda: ev.create_api_destination(
            Name=bad_name,
            ConnectionArn=bogus_conn_arn,
            InvocationEndpoint="https://example.com/webhook",
            HttpMethod="POST",
        )
    )
    expected = (
        "ResourceNotFoundException",
        f"Failed to create the api-destination(s). Connection '{bogus_conn_arn}' does not exist.",
    )
    assert err == expected, f"expected {expected}, got {err}"

    list_resp = ev.list_api_destinations(NamePrefix=bad_name)["ApiDestinations"]
    assert list_resp == [], "rejected CreateApiDestination must not create a resource"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
