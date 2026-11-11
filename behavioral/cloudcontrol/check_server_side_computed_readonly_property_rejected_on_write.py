"""server-side-computed-readonly-property-rejected-on-write."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "server-side-computed-readonly-property-rejected-on-write"
GROUP = "server-side"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An UpdateResource patch replacing a queue's read-only /Arn is refused synchronously with
    ValidationException and the exact readOnlyProperties diagnostic, the Arn reads back unchanged,
    and a patch of the writable VisibilityTimeout to 111 then succeeds."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    queue_name = ctx.unique_name("sim2real-behav-")
    desired_state = json.dumps({
        "QueueName": queue_name,
        "Tags": [{"Key": "sim2real", "Value": CHECK}],
    })

    progress = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)[
        "ProgressEvent"
    ]
    final = _wait_for_terminal(ctx, progress["RequestToken"])
    assert final["OperationStatus"] == "SUCCESS", f"create did not succeed: {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", identifier, teardown))

    original_props = _get_properties(ctx, "AWS::SQS::Queue", identifier)
    real_arn = original_props["Arn"]
    assert real_arn, "expected a real, service-computed Arn on the created queue"

    # (a) break exactly one thing: try to overwrite the read-only Arn via the patch.
    # Cloud Control refuses it at the front door, before any request token is minted.
    bogus_arn = "arn:aws:sqs:us-east-1:111122223333:sim2real-bogus-arn"
    patch = json.dumps([{"op": "replace", "path": "/Arn", "value": bogus_arn}])
    code, message = _error(
        lambda: cc.update_resource(
            TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=patch
        )
    )
    assert code == "ValidationException", f"unexpected error code for read-only patch: {code}"
    expected_message = "Invalid patch update: readOnlyProperties [/properties/Arn] cannot be updated"
    assert message == expected_message, (
        f"expected the read-only refusal {expected_message!r}, got {message!r}"
    )

    # (b) the effect is absent: the real Arn is untouched, the bogus value never took hold.
    after_props = _get_properties(ctx, "AWS::SQS::Queue", identifier)
    assert after_props["Arn"] == real_arn, "read-only Arn was mutated by a rejected patch"
    assert after_props["Arn"] != bogus_arn, (
        f"read-only Arn took the rejected patch's bogus value: {after_props['Arn']!r}"
    )

    # (c) positive control on the SAME resource: a legitimate patch to a writable property
    # still succeeds and is reflected on the next GetResource.
    good_patch = json.dumps([{"op": "replace", "path": "/VisibilityTimeout", "value": 111}])
    progress2 = cc.update_resource(
        TypeName="AWS::SQS::Queue", Identifier=identifier, PatchDocument=good_patch
    )["ProgressEvent"]
    final2 = _wait_for_terminal(ctx, progress2["RequestToken"])
    assert final2["OperationStatus"] == "SUCCESS", f"legitimate update did not succeed: {final2}"
    final_props = _get_properties(ctx, "AWS::SQS::Queue", identifier)
    assert int(final_props["VisibilityTimeout"]) == 111, (
        f"expected VisibilityTimeout 111 after legitimate patch, got {final_props['VisibilityTimeout']!r}"
    )


def _wait_for_terminal(ctx, request_token: str, timeout_s: float = 120.0) -> dict[str, Any]:
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(2)
    raise AssertionError(f"request {request_token} never reached a terminal state: {last}")


def _get_properties(ctx, type_name: str, identifier: str) -> dict[str, Any]:
    cc = ctx.client("cloudcontrol")
    desc = cc.get_resource(TypeName=type_name, Identifier=identifier)["ResourceDescription"]
    return json.loads(desc["Properties"])


def _error(fn) -> tuple[str, str | None]:
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"the read-only patch was expected to be refused but returned {result!r}")


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _request_outcome(cc, token: str, teardown) -> dict:
    """Poll GetResourceRequestStatus every 2 s until the request ends; return its ProgressEvent."""
    while True:
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if event["OperationStatus"] not in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            return event
        if time.monotonic() >= teardown.deadline():
            raise AssertionError(
                f"request {token} is still {event['OperationStatus']} at the cleanup deadline"
            )
        time.sleep(2)


def _delete_resource(cc, type_name: str, identifier: str, teardown) -> None:
    """DeleteResource and wait for its outcome; a NotFound answer means the resource is gone.

    ConcurrentOperationException and ResourceConflictException (another request holds the
    resource) are retried every 2 s to the shared cleanup deadline; anything else raises."""
    while True:
        try:
            resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConcurrentOperationException", "ResourceConflictException"):
                raise
            if time.monotonic() >= teardown.deadline():
                raise
            time.sleep(2)
    event = _request_outcome(cc, resp["ProgressEvent"]["RequestToken"], teardown)
    if event["OperationStatus"] == "FAILED" and event.get("ErrorCode") == "NotFound":
        return
    if event["OperationStatus"] != "SUCCESS":
        raise AssertionError(
            f"DeleteResource of {type_name} {identifier} ended {event['OperationStatus']}: {event}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
