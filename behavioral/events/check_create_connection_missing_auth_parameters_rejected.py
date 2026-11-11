"""create-connection-missing-auth-parameters-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-connection-missing-auth-parameters-rejected"
GROUP = 'connection'
SERVICES = ['events']

def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")

def _cleanup_connection(ev, name):
    """Best-effort DeleteConnection (asynchronous; the connection disappears later)."""
    try:
        ev.delete_connection(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _poll_connection_settled(ev, name, timeout_s=60.0):
    """Poll DescribeConnection until the state is terminal; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = ev.describe_connection(Name=name)
        if desc["ConnectionState"] in ("AUTHORIZED", "DEAUTHORIZED", "CREATE_FAILED"):
            return desc
        time.sleep(1)
    raise AssertionError(f"connection {name} did not settle within {timeout_s}s: {desc!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: CreateConnection with AuthorizationType=API_KEY but no ApiKeyAuthParameters must be rejected as a validation error, not accepted with empty credentials.

    A positive control proves the account accepts a well-formed API_KEY connection at all, so
    the rejection below cannot be "every CreateConnection fails" wearing a validation-shaped mask.
    """
    ev = ctx.client("events")

    control_name = ctx.unique_name("sim2real-behav-conn-ok-")
    ev.create_connection(
        Name=control_name,
        AuthorizationType="API_KEY",
        AuthParameters={
            "ApiKeyAuthParameters": {"ApiKeyName": "x-api-key", "ApiKeyValue": "secret-value"}
        },
    )
    ctx.on_cleanup(lambda: _cleanup_connection(ev, control_name))
    control_desc = _poll_connection_settled(ev, control_name)
    assert control_desc["ConnectionState"] == "AUTHORIZED", (
        f"positive control: expected ConnectionState AUTHORIZED, got {control_desc.get('ConnectionState')!r}"
    )

    name = ctx.unique_name("sim2real-behav-conn-")
    err = _error(
        lambda: ev.create_connection(Name=name, AuthorizationType="API_KEY", AuthParameters={})
    )
    expected = (
        "ValidationException",
        "Failed to create the connection(s). Parameter AuthParameters is not valid. Reason: "
        "The value for AuthParameters must include exactly one authorization type.",
    )
    assert err == expected, f"expected {expected}, got {err}"

    describe_err = _error(lambda: ev.describe_connection(Name=name))
    expected_absent = (
        "ResourceNotFoundException",
        f"Failed to describe the connection(s). Connection '{name}' does not exist.",
    )
    assert describe_err == expected_absent, (
        f"rejected CreateConnection must not leave a connection behind, got {describe_err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
