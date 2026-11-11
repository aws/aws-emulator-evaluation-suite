"""cancel-bogus-request-token-must-fail."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-bogus-request-token-must-fail"
GROUP = 'overly-permissive'
SERVICES = ['cloudcontrol']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelResourceRequest on a never-issued RequestToken fails with RequestTokenNotFoundException "Request
    with token <token> was not found" and the token is not in ListResourceRequests; on a completed request it
    fails with ValidationException "Request <token> is already in status SUCCESS"."""
    cc = ctx.client("cloudcontrol")

    # Positive control: a real, freshly submitted request token always resolves -- cancel refuses it
    # on the grounds of its own terminal state (ValidationException), never as unknown.
    name = ctx.unique_name("sim2real-behav-cancel-control-")
    progress = cc.create_resource(
        TypeName="AWS::SQS::Queue", DesiredState=json.dumps({"QueueName": name})
    )["ProgressEvent"]
    real_token = progress["RequestToken"]
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", real_token, teardown))
    final, _ = _wait_terminal(cc, real_token)
    assert final["OperationStatus"] == "SUCCESS", f"queue create failed: {final}"

    control_code, control_message = _client_error(
        lambda: cc.cancel_resource_request(RequestToken=real_token)
    )
    assert control_code == "ValidationException", (
        f"a just-submitted request token must resolve, not be treated as unknown, got {control_code}"
    )
    expected_control = f"Request {real_token} is already in status SUCCESS"
    assert control_message == expected_control, (
        f"expected message {expected_control!r}, got {control_message!r}"
    )

    # Negative: a well-formed but never-issued token must be rejected, not accepted as a no-op
    # success.
    bogus_token = str(uuid.uuid4())
    code, message = _client_error(lambda: cc.cancel_resource_request(RequestToken=bogus_token))
    assert code == "RequestTokenNotFoundException", (
        f"cancel of an unknown request token must fail, got {code}"
    )
    expected = f"Request with token {bogus_token} was not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Independent terminal read: the bogus token must also be absent from ListResourceRequests --
    # rejection reflects reality, it was never recorded as a request.
    found = _find_request(cc, bogus_token)
    assert found is None, f"bogus token unexpectedly appeared in ListResourceRequests: {found}"


def _client_error(fn):
    """The (code, message) of the ClientError fn() raises; raises if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_terminal(cc, request_token: str, timeout_s: float = 120.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    history: list[str] = []
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        history.append(last["OperationStatus"])
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last, history
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} never reached terminal status, last={last}")


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


def _find_request(cc, token: str, max_pages: int = 5) -> dict | None:
    kwargs: dict = {"MaxResults": 100}
    next_token = None
    for _ in range(max_pages):
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        for summary in resp.get("ResourceRequestStatusSummaries", []):
            if summary["RequestToken"] == token:
                return summary
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
