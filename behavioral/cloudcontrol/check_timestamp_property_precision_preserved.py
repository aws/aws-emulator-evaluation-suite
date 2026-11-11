"""timestamp-property-precision-preserved."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "timestamp-property-precision-preserved"
GROUP = "representation"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A topic tag value "2024-03-15T08:42:17.123456Z" reads back character for character through
    GetResource, not reformatted or truncated; after DeleteResource, GetResource answers
    ResourceNotFoundException with the SNS handler's not-found message."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    precise_timestamp = "2024-03-15T08:42:17.123456Z"
    topic_name = ctx.unique_name("sim2real-cc-tsprec-")
    desired_state = json.dumps(
        {"TopicName": topic_name, "Tags": [{"Key": "createdAt", "Value": precise_timestamp}]}
    )
    create_resp = cc.create_resource(TypeName="AWS::SNS::Topic", DesiredState=desired_state)
    event = _wait_for_progress(cc, create_resp["ProgressEvent"]["RequestToken"])
    assert event["OperationStatus"] == "SUCCESS", event
    topic_arn = event["Identifier"]
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SNS::Topic", topic_arn, teardown))

    props = _get_properties(cc, "AWS::SNS::Topic", topic_arn)
    tags = {t["Key"]: t["Value"] for t in props.get("Tags", [])}
    assert tags.get("createdAt") == precise_timestamp, (
        f"timestamp mangled: expected {precise_timestamp!r}, got {tags.get('createdAt')!r}"
    )

    delete_resp = cc.delete_resource(TypeName="AWS::SNS::Topic", Identifier=topic_arn)
    delete_event = _wait_for_progress(cc, delete_resp["ProgressEvent"]["RequestToken"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event
    code, message = _error(lambda: cc.get_resource(TypeName="AWS::SNS::Topic", Identifier=topic_arn))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetResource after delete, got {code!r}"
    )
    expected = _sns_topic_not_found(message)
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _wait_for_progress(cc, request_token: str, timeout_s: float = 180.0, interval_s: float = 2.0) -> dict:
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if last.get("OperationStatus") in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state; last={last}")


def _get_properties(cc, type_name: str, identifier: str) -> dict:
    resp = cc.get_resource(TypeName=type_name, Identifier=identifier)
    return json.loads(resp["ResourceDescription"]["Properties"])


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so a
    target that accepts what AWS refuses is never read as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _sns_topic_not_found(message):
    """The SNS handler's NotFound text; its request ids and attempt count vary per call, so they are read back."""
    found = re.search(r"Request ID: ([^)]*)\) \(SDK Attempt Count: (\d+)\) .*RequestToken: ([^)]*)\)$", message)
    request_id, attempts, token = found.groups() if found else ("<id>", "<n>", "<token>")
    return (
        "AWS::SNS::Topic Handler returned status FAILED: Topic does not exist (Service: Sns, Status Code: 404, "
        f"Request ID: {request_id}) (SDK Attempt Count: {attempts}) (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


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
