"""list-resource-requests-time-window-filter."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-requests-time-window-filter"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_QUEUE_TYPE = "AWS::SQS::Queue"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests with OperationStatuses=["SUCCESS"] includes a succeeded request and
    ["FAILED"] excludes it; after deletion GetResource is ResourceNotFoundException.
    """
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    name = ctx.unique_name("sim2real-cc-listfilter-")
    create_resp = cc.create_resource(
        TypeName=_QUEUE_TYPE,
        DesiredState=json.dumps(
            {"QueueName": name, "Tags": [{"Key": "sim2real-audit", "Value": CHECK}]}
        ),
    )
    token = create_resp["ProgressEvent"]["RequestToken"]
    final = _poll_terminal(cc, token, timeout_s=90.0)
    identifier = final.get("Identifier")
    ctx.on_cleanup(lambda: _cleanup_request(cc, _QUEUE_TYPE, token, teardown))
    assert final["OperationStatus"] == "SUCCESS", final

    # The API has no request-time filter (botocore rejects one); OperationStatuses is graded.
    included = _find_token(cc, token, operation_statuses=["SUCCESS"])
    assert included is not None, "expected the SUCCESS request under an OperationStatuses=[SUCCESS] filter"
    assert included["RequestToken"] == token, included
    assert included["OperationStatus"] == "SUCCESS", included
    assert included["TypeName"] == _QUEUE_TYPE, included

    excluded = _find_token(cc, token, operation_statuses=["FAILED"])
    assert excluded is None, "a SUCCESS request must not appear when filtering strictly for FAILED"

    delete_resp = cc.delete_resource(TypeName=_QUEUE_TYPE, Identifier=identifier)
    delete_final = _poll_terminal(cc, delete_resp["ProgressEvent"]["RequestToken"], timeout_s=180.0)
    assert delete_final["OperationStatus"] == "SUCCESS", delete_final

    not_found_code, not_found_message = _error_code(
        lambda: cc.get_resource(TypeName=_QUEUE_TYPE, Identifier=identifier)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a deleted queue, got {not_found_code!r}"
    )
    expected = _handler_not_found(not_found_message, _queue_not_found_detail(identifier))
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


#: A RequestToken: a lowercase UUID.
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


def _handler_not_found(message, detail):
    """The handler's NotFound text; its RequestToken (a UUID) is minted per call, so it is read back."""
    token = message.rpartition("RequestToken: ")[2].removesuffix(")")
    token = token if re.fullmatch(_UUID, token) else "<a UUID>"
    return f"{detail} (HandlerErrorCode: NotFound, RequestToken: {token})"


def _queue_not_found_detail(queue_url):
    return (
        "AWS::SQS::Queue Handler returned status FAILED: Resource of type 'AWS::SQS::Queue' "
        f"with identifier '{queue_url}' was not found."
    )


def _poll_terminal(cc, token, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request did not reach terminal state within {timeout_s}s; last={last}")


def _find_token(cc, target_token, operation_statuses, max_pages=20):
    """The ListResourceRequests summary for target_token under OperationStatuses, or None."""
    next_token = None
    for _ in range(max_pages):
        kwargs = {
            "MaxResults": 100,
            "ResourceRequestStatusFilter": {"OperationStatuses": operation_statuses},
        }
        if next_token:
            kwargs["NextToken"] = next_token
        page = cc.list_resource_requests(**kwargs)
        for summary in page.get("ResourceRequestStatusSummaries", []):
            if summary.get("RequestToken") == target_token:
                return summary
        next_token = page.get("NextToken")
        if not next_token:
            break
    return None


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


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
