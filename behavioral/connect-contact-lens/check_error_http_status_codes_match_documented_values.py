"""error-http-status-codes-match-documented-values."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "error-http-status-codes-match-documented-values"
GROUP = "error-semantics"
SERVICES = ["connect-contact-lens"]

NOT_FOUND = "Real-time contact analysis not found."
BAD_CONTACT = "   "
PATTERN_MISMATCH = (
    'Invalid request body: [ECMA 262 regex ".*\\S.*" does not match input string '
    f'"{BAD_CONTACT}"]'
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListRealtimeContactAnalysisSegments fails with InvalidRequestException on HTTP 400 for a pattern
    mismatch and with ResourceNotFoundException on HTTP 404 for an unknown contact, each with its exact
    message and no Segments; an ACTIVE instance exists so the authorizer evaluates the input."""
    connect = ctx.client("connect")
    client = ctx.client("connect-contact-lens")
    _create_active_instance(ctx, connect)
    fake_instance = str(uuid.uuid4())

    try:
        resp = client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=BAD_CONTACT
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidRequestException", (
            f"expected InvalidRequestException for a whitespace-only ContactId, got {code!r}"
        )
        message = err.response["Error"]["Message"]
        assert message == PATTERN_MISMATCH, (
            f"unexpected InvalidRequestException message {message!r}"
        )
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 400, f"expected HTTP 400 for InvalidRequestException, got {status!r}"
        assert "Segments" not in err.response, (
            f"expected no Segments key in the error body, got {err.response!r}"
        )
    else:
        raise AssertionError(f"expected InvalidRequestException, got 200: {resp}")

    try:
        resp = client.list_realtime_contact_analysis_segments(
            InstanceId=fake_instance, ContactId=str(uuid.uuid4())
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for a well-formed but nonexistent "
            f"ContactId, got {code!r}"
        )
        message = err.response["Error"]["Message"]
        assert message == NOT_FOUND, (
            f"unexpected ResourceNotFoundException message {message!r}"
        )
        status = err.response["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 404, f"expected HTTP 404 for ResourceNotFoundException, got {status!r}"
        assert "Segments" not in err.response, (
            f"expected no Segments key in the error body, got {err.response!r}"
        )
    else:
        raise AssertionError(f"expected ResourceNotFoundException, got 200: {resp}")


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
