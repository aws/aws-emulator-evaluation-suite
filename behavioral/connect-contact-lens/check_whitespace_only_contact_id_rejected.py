"""whitespace-only-contact-id-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "whitespace-only-contact-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["connect-contact-lens"]


NOT_FOUND = "Real-time contact analysis not found."
BAD_CONTACT = "     "
PATTERN_MISMATCH = (
    'Invalid request body: [ECMA 262 regex ".*\\S.*" does not match input string '
    f'"{BAD_CONTACT}"]'
)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    over-permissive target accepting input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(
        f"expected a rejection, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments on an ACTIVE instance with a whitespace-only ContactId fails with
    HTTP 400 InvalidRequestException and its exact message and no Segments, while a well-formed ContactId
    fails with ResourceNotFoundException."""
    connect = ctx.client("connect")
    client = ctx.client("connect-contact-lens")
    alias = ctx.unique_name("sim2real-behav-")

    instance = connect.create_instance(
        IdentityManagementType="CONNECT_MANAGED",
        InstanceAlias=alias,
        InboundCallsEnabled=True,
        OutboundCallsEnabled=True,
        Tags={"sim2real": "whitespace-only-contact-id-rejected"},
    )
    instance_id = instance["Id"]
    ctx.on_cleanup(lambda: _delete_instance(connect, instance_id))
    active = _wait_for_instance_status(connect, instance_id, "ACTIVE")
    assert active["InstanceStatus"] == "ACTIVE", (
        f'expected the prerequisite instance to reach "ACTIVE", got '
        f'{active["InstanceStatus"]!r}'
    )

    broken = None
    try:
        resp = client.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=BAD_CONTACT
        )
    except ClientError as err:
        broken = err.response
    else:
        raise AssertionError(
            f"expected InvalidRequestException, got a 200 response instead: {resp}"
        )

    assert broken["Error"]["Code"] == "InvalidRequestException", (
        f'expected error code "InvalidRequestException", got {broken["Error"]["Code"]!r}'
    )
    assert broken["Error"]["Message"] == PATTERN_MISMATCH, (
        f"unexpected InvalidRequestException message {broken['Error']['Message']!r}"
    )
    assert broken["ResponseMetadata"]["HTTPStatusCode"] == 400, (
        f'expected HTTP status 400, got {broken["ResponseMetadata"]["HTTPStatusCode"]!r}'
    )
    # effect absent: no data-plane content leaks out alongside the rejection
    assert "Segments" not in broken, (
        f'expected no "Segments" key alongside the rejection, but found one: {broken!r}'
    )

    # positive control: the SAME (real, ACTIVE) instance with a well-formed (still
    # nonexistent) ContactId must produce a *different* code -- proving the whitespace
    # value, not a blanket rejection of every request against this instance, caused
    # the 400 above.
    control = _error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=str(uuid.uuid4())
        )
    )
    assert control["Code"] == "ResourceNotFoundException", (
        f"well-formed ContactId control produced {control['Code']!r}, expected "
        "ResourceNotFoundException"
    )
    assert control["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {control['Message']!r}"
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
