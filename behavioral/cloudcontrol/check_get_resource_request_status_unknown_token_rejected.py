"""get-resource-request-status-unknown-token-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-resource-request-status-unknown-token-rejected"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetResourceRequestStatus of a never-issued UUID RequestToken is refused with
    RequestTokenNotFoundException and "Request with token <token> was not found" and the token is
    not listed by ListResourceRequests, while the token of a create this check submitted reads SUCCESS."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    # Positive control: a real, freshly submitted request token is always resolvable.
    name = ctx.unique_name("sim2real-cc-neg-")
    desired_state = json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]})
    progress = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired_state)["ProgressEvent"]
    real_token = progress["RequestToken"]
    final, _ = _wait_terminal(cc, real_token)
    assert final["OperationStatus"] == "SUCCESS", f"queue create failed: {final}"
    ctx.on_cleanup(lambda: _delete_resource(cc, "AWS::SQS::Queue", final["Identifier"], teardown))

    control_event = cc.get_resource_request_status(RequestToken=real_token)["ProgressEvent"]
    assert control_event["RequestToken"] == real_token, (
        f"expected control read to echo token {real_token}, got {control_event['RequestToken']}"
    )
    assert control_event["OperationStatus"] == "SUCCESS", (
        f"expected control token to read back SUCCESS, got {control_event['OperationStatus']}"
    )

    # Negative: a well-formed but never-issued token must be rejected, and must not leak any
    # request state (no OperationStatus is returned at all -- the call raises).
    bogus_token = str(uuid.uuid4())
    code, message = _error(lambda: cc.get_resource_request_status(RequestToken=bogus_token))
    assert code == "RequestTokenNotFoundException", f"expected RequestTokenNotFoundException, got {code}"
    assert message == f"Request with token {bogus_token} was not found", (
        f"the refusal must name the unknown token, got {message!r}"
    )

    # The bogus token must also be absent from ListResourceRequests -- rejection reflects
    # reality, it did not silently get recorded as a request.
    found = _find_request(cc, bogus_token)
    assert found is None, f"bogus token unexpectedly appeared in ListResourceRequests: {found}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts a call AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but call SUCCEEDED and returned {result!r}")


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
