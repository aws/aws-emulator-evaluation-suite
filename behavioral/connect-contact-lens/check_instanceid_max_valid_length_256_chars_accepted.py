"""instanceid-max-valid-length-256-chars-accepted."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instanceid-max-valid-length-256-chars-accepted"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]

UNAUTHORIZED = "Unauthorized"
NOT_FOUND = "Real-time contact analysis not found."


def _error(fn):
    """Call fn(); return the botocore error response. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments with a 256-character InstanceId is not refused as too long: a
    non-GUID value fails with UnauthorizedException and a GUID-shaped one with ResourceNotFoundException,
    each with its exact message; an ACTIVE instance exists so the authorizer evaluates the input."""
    connect = ctx.client("connect")
    lens = ctx.client("connect-contact-lens")
    _create_active_instance(ctx, connect)

    base = str(uuid.uuid4())
    padded_instance_id = (base + "a" * 256)[:256]
    assert len(padded_instance_id) == 256, (
        f"test setup: expected a 256-char padded id, got length {len(padded_instance_id)}"
    )

    error = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=padded_instance_id, ContactId=str(uuid.uuid4())
        )
    )["Error"]
    assert error["Code"] == "UnauthorizedException", (
        f"exactly-256-char non-GUID-shaped InstanceId produced {error['Code']!r}, expected "
        "UnauthorizedException (it is not rejected as too long)"
    )
    assert error["Message"] == UNAUTHORIZED, (
        f"unexpected UnauthorizedException message {error['Message']!r}"
    )

    # control: a canonical (still-nonexistent) GUID-shaped InstanceId clears instance
    # resolution and reaches the contact lookup, so the refusal above is about the
    # id's shape, not a blanket refusal of every call.
    control = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=str(uuid.uuid4()), ContactId=str(uuid.uuid4())
        )
    )["Error"]
    assert control["Code"] == "ResourceNotFoundException", (
        f"canonical-GUID-shaped InstanceId control produced {control['Code']!r}, "
        "expected ResourceNotFoundException"
    )
    assert control["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {control['Message']!r}"
    )


def _create_active_instance(ctx, connect, timeout_s=270.0, interval_s=5.0):
    """A new Connect instance, waited to ACTIVE."""
    instance_id = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=ctx.unique_name("sim2real-behav-"),
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = connect.describe_instance(InstanceId=instance_id)["Instance"]
        if last["InstanceStatus"] == "ACTIVE":
            return instance_id
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached ACTIVE, last={last}")


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
