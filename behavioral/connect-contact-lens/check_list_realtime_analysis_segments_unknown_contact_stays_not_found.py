"""list-realtime-analysis-segments-unknown-contact-stays-not-found."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-realtime-analysis-segments-unknown-contact-stays-not-found"
GROUP = "state-machine"
SERVICES = ["connect-contact-lens"]


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A never-existed contact's real-time analysis stays ResourceNotFoundException
    with no NextToken or Segments across repeated polls over real time, so it never
    turns into an in-progress session just because it was asked again."""
    connect = ctx.client("connect")
    lens = ctx.client("connect-contact-lens")
    alias = ctx.unique_name("sim2real-behav-")

    instance = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"env": "sim2real"},
    )
    instance_id = instance["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))

    _wait_for_instance_status(connect, instance_id, "ACTIVE")

    fake_contact = str(uuid.uuid4())

    def probe():
        try:
            resp = lens.list_realtime_contact_analysis_segments(
                InstanceId=instance_id, ContactId=fake_contact
            )
        except ClientError as err:
            return err.response
        raise AssertionError(f"expected ResourceNotFoundException, got 200: {resp}")

    # bounded poll: the "no session, terminal" contract must hold on the first
    # call AND keep holding across several polls spread over real time -- a
    # contact that never existed must never spontaneously become "in progress"
    # just because we asked again a moment later.
    deadline = time.monotonic() + 20.0
    polls = 0
    while time.monotonic() < deadline:
        error_response = probe()
        assert error_response["Error"]["Code"] == "ResourceNotFoundException"
        assert error_response["Error"]["Message"] == "Real-time contact analysis not found.", (
            f'expected the exact ResourceNotFoundException message AWS returns, got {error_response["Error"]["Message"]!r}'
        )
        assert "NextToken" not in error_response
        assert "Segments" not in error_response
        polls += 1
        time.sleep(2.0)
    assert polls >= 3, f"only completed {polls} polls in the poll window, expected >= 3"


def _wait_for_instance_status(connect, instance_id, status, timeout_s=240.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = connect.describe_instance(InstanceId=instance_id)
        last = resp["Instance"]
        if last["InstanceStatus"] == status:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"instance {instance_id} never reached {status}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
