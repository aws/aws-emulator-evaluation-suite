"""not-found-for-nonexistent-instance-and-contact."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "not-found-for-nonexistent-instance-and-contact"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]


NOT_FOUND = "Real-time contact analysis not found."
BAD_CONTACT = "   "
PATTERN_MISMATCH = (
    'Invalid request body: [ECMA 262 regex ".*\\S.*" does not match input string '
    f'"{BAD_CONTACT}"]'
)


def _error(fn):
    """Call fn(); return the botocore error response. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments with a well-formed made-up InstanceId and ContactId fails with
    HTTP 404 ResourceNotFoundException and its exact message, not an empty Segments list, while a pattern
    mismatch fails with InvalidRequestException; an ACTIVE instance exists so the input is evaluated."""
    connect = ctx.client("connect")
    client = ctx.client("connect-contact-lens")
    _create_active_instance(ctx, connect)
    fake_instance = str(uuid.uuid4())
    fake_contact = str(uuid.uuid4())

    try:
        resp = client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=fake_contact
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got {code!r}"
        )
        message = err.response["Error"]["Message"]
        assert message == NOT_FOUND, f"unexpected ResourceNotFoundException message {message!r}"
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 404, f"expected HTTP 404, got {status!r}"
        # the error body must not leak partial data-plane content
        assert "Segments" not in err.response, (
            f"expected no Segments key in the error body, got {err.response!r}"
        )
    else:
        raise AssertionError(
            f"expected ResourceNotFoundException, got a 200 response instead: {resp}"
        )

    # positive control: on the SAME fake instance, a malformed (whitespace-only)
    # ContactId must produce a DIFFERENT code -- proving the ResourceNotFoundException
    # above is a genuine existence check on a well-formed identifier, not a blanket
    # rejection of every ListRealtimeContactAnalysisSegments call regardless of input.
    control = _error(
        lambda: client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=BAD_CONTACT
        )
    )["Error"]
    assert control["Code"] == "InvalidRequestException", (
        f"malformed-ContactId control produced {control['Code']!r}, expected "
        "InvalidRequestException"
    )
    assert control["Message"] == PATTERN_MISMATCH, (
        f"unexpected InvalidRequestException message {control['Message']!r}"
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
