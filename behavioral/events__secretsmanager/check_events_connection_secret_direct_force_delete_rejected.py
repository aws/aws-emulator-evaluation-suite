"""events-connection-secret-direct-force-delete-rejected."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-connection-secret-direct-force-delete-rejected"

GROUP = "cross-service"

SERVICES = ["events", "secretsmanager"]


@tags("axis:rejection", "concern:e2e", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """Force-deleting an EventBridge Connection's secret via Secrets Manager is refused (owned by
    events), leaving the key and the AUTHORIZED connection intact; DeleteConnection removes it.
    """
    events = ctx.client("events")
    secrets = ctx.client("secretsmanager")

    key_name = "x-sim2real-api-key"
    key_value = _xname(ctx, "keyval")

    name = _xname(ctx, "conn")
    events.create_connection(
        Name=name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": key_name, "ApiKeyValue": key_value}
        },
    )
    ctx.on_cleanup(
        lambda: _quiet(lambda: ctx.client("events").delete_connection(Name=name))
    )
    described = _poll_until(
        lambda: events.describe_connection(Name=name),
        lambda d: d.get("ConnectionState") == "AUTHORIZED",
        timeout_s=180.0,
        interval_s=3.0,
        description=f"connection {name} reached AUTHORIZED",
    )
    secret_arn = described["SecretArn"]

    before = json.loads(_get_secret_string(secrets, secret_arn))
    assert _h(before["api_key_value"]) == _h(key_value), (
        f"setup is not sound: the secret at {secret_arn} does not hold the configured key (stored "
        f"sha256 {_h(before['api_key_value'])}, configured sha256 {_h(key_value)})"
    )

    # Force delete only: a RecoveryWindowInDays delete is accepted on this secret and schedules a
    # deletion 7 days out that nothing can clear.
    refusal = _error_code(
        lambda: secrets.delete_secret(
            SecretId=secret_arn, ForceDeleteWithoutRecovery=True
        )
    )
    expected_refusal = ("InvalidRequestException", "Operation is not allowed on secret owned by events")
    assert refusal == expected_refusal, (
        f"DeleteSecret(ForceDeleteWithoutRecovery=True) on the EventBridge-owned secret "
        f"{secret_arn!r} answered {refusal!r}, expected {expected_refusal!r}"
    )

    after = json.loads(_get_secret_string(secrets, secret_arn))
    assert _h(after["api_key_value"]) == _h(key_value), (
        f"the refused DeleteSecret still changed the stored credential: stored sha256 now "
        f"{_h(after['api_key_value'])}, configured sha256 {_h(key_value)}"
    )
    meta = secrets.describe_secret(SecretId=secret_arn)
    assert meta.get("DeletedDate") is None, (
        f"the refused DeleteSecret still scheduled the secret for deletion: DescribeSecret reports "
        f"DeletedDate={meta.get('DeletedDate')!r}"
    )
    assert meta.get("OwningService") == "events", (
        f"the secret's OwningService changed to {meta.get('OwningService')!r} during a call that was "
        f"refused"
    )
    state = events.describe_connection(Name=name)["ConnectionState"]
    assert state == "AUTHORIZED", (
        f"the refused DeleteSecret still disturbed the connection: DescribeConnection reports "
        f"ConnectionState={state!r}, expected 'AUTHORIZED'"
    )

    # DeleteConnection first marks the secret for deletion (GetSecretValue answers
    # InvalidRequestException) and removes it seconds later, so poll for the settled code.
    events.delete_connection(Name=name)
    gone = _poll_until(
        lambda: _error_code(lambda: secrets.get_secret_value(SecretId=secret_arn)),
        lambda c: c[0] == "ResourceNotFoundException",
        timeout_s=300.0,
        interval_s=5.0,
        description=(
            f"secret {secret_arn} removed with its connection (GetSecretValue settling on "
            f"ResourceNotFoundException)"
        ),
    )
    expected_gone = ("ResourceNotFoundException", "Secrets Manager can't find the specified secret.")
    assert gone == expected_gone, (
        f"after DeleteConnection, GetSecretValue on {secret_arn!r} settled on {gone!r}, expected "
        f"{expected_gone!r} -- the credential outlived the connection that owned it"
    )
    conn_gone = _error_code(lambda: events.describe_connection(Name=name))
    expected_conn_gone = ("ResourceNotFoundException", (
        f"Failed to describe the connection(s). Connection '{name}' does not exist."
    ))
    assert conn_gone == expected_conn_gone, (
        f"after DeleteConnection, DescribeConnection answered {conn_gone!r}, expected "
        f"{expected_conn_gone!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _h(value: str) -> str:
    """A short sha256 digest, so a failure message can name a credential without printing one."""
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _quiet(fn) -> None:
    """Teardown helper: a delete that races another delete must not mask a verdict."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error_code(fn):
    """Return (error code, message) for a failing call, or a non-falsy sentinel plus the response
    when the call unexpectedly succeeds, so an acceptance never reads like a code mismatch."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "<call unexpectedly SUCCEEDED>", resp


def _get_secret_string(secrets, secret_id: str) -> str:
    resp = secrets.get_secret_value(SecretId=secret_id)
    value = resp.get("SecretString")
    assert value, (
        f"GetSecretValue on {secret_id!r} returned no SecretString (keys "
        f"{sorted(resp.keys())!r})"
    )
    return value


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
