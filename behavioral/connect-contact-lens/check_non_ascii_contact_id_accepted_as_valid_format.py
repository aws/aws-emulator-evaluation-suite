"""non-ascii-contact-id-accepted-as-valid-format."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "non-ascii-contact-id-accepted-as-valid-format"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]

NOT_FOUND = "Real-time contact analysis not found."


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING an id real AWS would resolve straight to ResourceNotFoundException is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments with a non-ASCII ContactId passes the `.*\\S.*` pattern and fails
    with HTTP 404 ResourceNotFoundException and its exact message, like an ASCII one; an ACTIVE instance
    exists so the authorizer evaluates the input."""
    connect = ctx.client("connect")
    client = ctx.client("connect-contact-lens")
    _create_active_instance(ctx, connect)
    fake_instance = str(uuid.uuid4())
    # non-whitespace, non-ASCII characters mixed with a unique suffix
    fake_contact = "\u5951\u7d04-\u00e9\u00e8\u00ea-" + str(uuid.uuid4())

    broken = _client_error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=fake_contact
        )
    )
    assert broken["Error"]["Code"] == "ResourceNotFoundException", (
        f"non-ASCII ContactId produced unexpected code {broken['Error']['Code']!r}"
    )
    assert broken["Error"]["Message"] == NOT_FOUND, (
        f"non-ASCII ContactId produced unexpected message {broken['Error']['Message']!r}"
    )
    assert broken["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        "non-ASCII ContactId's ResourceNotFoundException rode an unexpected HTTP "
        f"status {broken['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    # effect absent: no data-plane content leaks out alongside the not-found
    assert "Segments" not in broken, (
        f"ResourceNotFoundException response unexpectedly carried Segments: {broken!r}"
    )

    # control: the SAME instance with a plain-ASCII (still nonexistent) ContactId
    # must land on the IDENTICAL code -- isolating the non-ASCII characters as the
    # thing under test, not some other quirk of this fake_instance/fake_contact pair.
    control = _client_error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=str(uuid.uuid4())
        )
    )
    assert control["Error"]["Code"] == "ResourceNotFoundException", (
        "plain-ASCII ContactId control produced "
        f"{control['Error']['Code']!r}, expected ResourceNotFoundException"
    )
    assert control["Error"]["Message"] == NOT_FOUND, (
        f"plain-ASCII ContactId control produced message {control['Error']['Message']!r}"
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
