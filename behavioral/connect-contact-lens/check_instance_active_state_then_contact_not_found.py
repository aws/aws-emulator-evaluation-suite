"""instance-active-state-then-contact-not-found."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "instance-active-state-then-contact-not-found"
GROUP = "state-machine"
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
    """A new Connect instance reaches ACTIVE, and ListRealtimeContactAnalysisSegments on it with a made-up
    ContactId fails with ResourceNotFoundException and its exact message."""
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

    active = _wait_for_instance_status(connect, instance_id, "ACTIVE")
    assert active["InstanceStatus"] == "ACTIVE", (
        f"expected instance {instance_id} to reach ACTIVE, got {active['InstanceStatus']!r}"
    )

    fake_contact = str(uuid.uuid4())
    error = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=fake_contact
        )
    )["Error"]
    assert error["Code"] == "ResourceNotFoundException", (
        f"real ACTIVE instance + unknown contact produced {error['Code']!r}"
    )
    assert error["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {error['Message']!r}"
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


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
