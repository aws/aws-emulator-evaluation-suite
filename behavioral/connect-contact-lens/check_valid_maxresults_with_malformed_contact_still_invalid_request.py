"""valid-maxresults-with-malformed-contact-still-invalid-request."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "valid-maxresults-with-malformed-contact-still-invalid-request"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]


NOT_FOUND = "Real-time contact analysis not found."
BAD_CONTACT = "   "
PATTERN_MISMATCH_WITH_MAX_RESULTS = (
    'Invalid request body: [ECMA 262 regex ".*\\S.*" does not match input string '
    f'"{BAD_CONTACT}", format attribute "int32" not supported]'
)


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments on an ACTIVE instance with a valid MaxResults and a malformed
    ContactId fails with InvalidRequestException and its exact message, while a well-formed ContactId
    with the same MaxResults fails with ResourceNotFoundException."""
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
    assert active["InstanceStatus"] == "ACTIVE"

    broken = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=BAD_CONTACT, MaxResults=100
        )
    )
    assert broken["Code"] == "InvalidRequestException", (
        f"malformed ContactId with valid MaxResults against a real ACTIVE instance "
        f"produced {broken['Code']!r}"
    )
    assert broken["Message"] == PATTERN_MISMATCH_WITH_MAX_RESULTS, (
        f"unexpected InvalidRequestException message {broken['Message']!r}"
    )

    control = _error(
        lambda: lens.list_realtime_contact_analysis_segments(
            InstanceId=instance_id, ContactId=str(uuid.uuid4()), MaxResults=100
        )
    )
    assert control["Code"] == "ResourceNotFoundException", (
        f"well-formed ContactId with valid MaxResults against a real ACTIVE instance "
        f"produced {control['Code']!r}"
    )
    assert control["Message"] == NOT_FOUND, (
        f"unexpected ResourceNotFoundException message {control['Message']!r}"
    )


def _delete_instance(connect, instance_id):
    try:
        connect.delete_instance(InstanceId=instance_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
