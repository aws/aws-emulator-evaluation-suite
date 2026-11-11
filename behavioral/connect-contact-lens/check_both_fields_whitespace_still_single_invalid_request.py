"""both-fields-whitespace-still-single-invalid-request."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "both-fields-whitespace-still-single-invalid-request"
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
    """ListRealtimeContactAnalysisSegments with all-whitespace InstanceId and ContactId fails with one
    UnauthorizedException and its exact message and no Segments, while well-formed nonexistent values
    fail with ResourceNotFoundException; an ACTIVE instance exists so the authorizer evaluates the input."""
    connect = ctx.client("connect")
    client = ctx.client("connect-contact-lens")
    _create_active_instance(ctx, connect)

    broken = _error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId="   ", ContactId="\t\t\t"
        )
    )
    assert broken["Error"]["Code"] == "UnauthorizedException", (
        f"expected UnauthorizedException, got {broken['Error']['Code']!r}"
    )
    assert broken["Error"]["Message"] == UNAUTHORIZED, (
        f"unexpected UnauthorizedException message {broken['Error']['Message']!r}"
    )
    assert "Segments" not in broken, f"error response leaked Segments: {broken}"

    # positive control: well-formed (still nonexistent) values for BOTH fields must
    # produce a *different* code -- proving the whitespace pair, not a blanket
    # rejection of every call, caused the error above.
    control = _error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId=str(uuid.uuid4()), ContactId=str(uuid.uuid4())
        )
    )["Error"]
    assert control["Code"] == "ResourceNotFoundException", (
        f"well-formed InstanceId/ContactId control produced {control['Code']!r}, "
        "expected ResourceNotFoundException"
    )
    assert control["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {control['Message']!r}"
    )


def _create_active_instance(ctx, connect, timeout_s=240.0, interval_s=5.0):
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
