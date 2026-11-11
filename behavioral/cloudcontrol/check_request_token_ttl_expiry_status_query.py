"""request-token-ttl-expiry-status-query."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "request-token-ttl-expiry-status-query"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus of a never-issued UUID RequestToken (as for one past the 7-day
    retention) is refused with RequestTokenNotFoundException and "Request with token <token> was not
    found", while a just-issued queue-create token resolves to its CREATE request reaching SUCCESS."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    bogus_token = str(uuid.uuid4())
    code, message = _error(lambda: cc.get_resource_request_status(RequestToken=bogus_token))
    assert code == "RequestTokenNotFoundException", (
        f"expected RequestTokenNotFoundException for a never-issued token, got {code}"
    )
    expected_message = f"Request with token {bogus_token} was not found"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # positive control: a token issued by a real, just-submitted request resolves fine, and
    # tracks the request all the way to its terminal, independently-read outcome.
    name = ctx.unique_name("sim2real-cc-ttlpos-")
    create_resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
    )
    real_token = create_resp["ProgressEvent"]["RequestToken"]
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", real_token, teardown))

    event = _wait_terminal(cc, real_token)
    assert event["RequestToken"] == real_token, (
        f"expected ProgressEvent to echo back {real_token!r}, got {event.get('RequestToken')!r}"
    )
    assert event["TypeName"] == "AWS::SQS::Queue", (
        f"expected TypeName 'AWS::SQS::Queue', got {event.get('TypeName')!r}"
    )
    assert event["Operation"] == "CREATE", f"expected Operation 'CREATE', got {event.get('Operation')!r}"
    assert event["OperationStatus"] == "SUCCESS", (
        f"expected the just-submitted request to reach SUCCESS, got {event['OperationStatus']} "
        f"(detail={event.get('StatusMessage')!r})"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected RequestTokenNotFoundException, but the call succeeded and returned {result!r}"
    )


def _wait_terminal(cc, request_token, timeout_s: float = 150.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    history = []
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        history.append(last["OperationStatus"])
        if last["OperationStatus"] in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"request {request_token} did not reach a terminal state within {timeout_s}s (history={history})"
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


def _cleanup_request(cc, type_name: str, token: str, teardown) -> None:
    """Wait for a create request to end, then delete the resource it made."""
    event = _request_outcome(cc, token, teardown)
    if event["OperationStatus"] == "SUCCESS":
        _delete_resource(cc, type_name, event["Identifier"], teardown)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
