"""deleted-instance-lookup-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deleted-instance-lookup-rejected"
GROUP = "overly-permissive"
SERVICES = ["connect-contact-lens"]

NOT_FOUND = "Real-time contact analysis not found."


def _error(fn):
    """Call fn(); return the botocore error response. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments on a deleted Connect instance that was ACTIVE fails with
    ResourceNotFoundException and its exact message, as does DescribeInstance ("Instance <id> not found")."""
    connect = ctx.client("connect")
    lens = ctx.client("connect-contact-lens")
    alias = ctx.unique_name("sim2real-behav-")

    instance = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": CHECK},
    )
    instance_id = instance["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))

    # drive the instance to ACTIVE -- this is the genuine positive control: the
    # instance really exists and really works before we delete it.
    active_instance = _wait_for_instance_status(connect, instance_id, "ACTIVE")
    assert active_instance["InstanceStatus"] == "ACTIVE", (
        f"expected positive control to reach ACTIVE, got {active_instance['InstanceStatus']!r}"
    )

    fake_contact = str(uuid.uuid4())

    # break exactly one thing: delete the (real, active) instance
    connect.delete_instance(InstanceId=instance_id)
    _wait_for_instance_gone(connect, instance_id)

    # effect: the deleted instance is unusable via ListRealtimeContactAnalysisSegments
    error = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=fake_contact
        )
    )["Error"]
    assert error["Code"] == "ResourceNotFoundException", (
        f"deleted instance produced {error['Code']!r}, expected ResourceNotFoundException"
    )
    assert error["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {error['Message']!r}"
    )

    # effect (control): DescribeInstance on the same id also now reports gone,
    # confirming this is genuine deletion, not an isolated fault in the
    # contact-lens API path specifically
    describe_error = _error(lambda: connect.describe_instance(InstanceId=instance_id))["Error"]
    assert describe_error["Code"] == "ResourceNotFoundException", (
        f"deleted instance's own DescribeInstance produced {describe_error['Code']!r}, "
        "expected ResourceNotFoundException"
    )
    assert describe_error["Message"] == f"Instance {instance_id} not found", (
        f"unexpected DescribeInstance message {describe_error['Message']!r}"
    )


def _wait_for_instance_status(connect, instance_id, status, timeout_s=270.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = connect.describe_instance(InstanceId=instance_id)
        last = resp["Instance"]
        if last["InstanceStatus"] == status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached {status}, last={last}")


def _wait_for_instance_gone(connect, instance_id, timeout_s=270.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            connect.describe_instance(InstanceId=instance_id)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} was not deleted within {timeout_s}s")


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
