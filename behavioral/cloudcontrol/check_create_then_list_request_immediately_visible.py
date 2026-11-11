"""create-then-list-request-immediately-visible."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-then-list-request-immediately-visible"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A just-submitted CreateResource request is found within 60 s by paginating ListResourceRequests for its token
    (the listing guarantees no order, so no head position is assumed), and the request then ends SUCCESS."""
    cc = ctx.client("cloudcontrol")
    name = ctx.unique_name("sim2real-cc-immediate-")
    desired = json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real-check", "Value": CHECK}]})

    resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired)
    token = resp["ProgressEvent"]["RequestToken"]
    teardown = _Teardown()
    ctx.on_cleanup(lambda: _cleanup_request(cc, "AWS::SQS::Queue", token, teardown))

    found = _poll_until_visible(cc, token, timeout_s=60.0)
    assert found is not None, (
        f"expected freshly submitted request {token} to become visible in "
        f"ListResourceRequests within 60s, never found"
    )

    # The create request itself ends SUCCESS.
    final = _poll_progress(cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"create queue {name} did not succeed: {final}"


def _poll_until_visible(cc, token, timeout_s=60.0, interval_s=1.0, page_size=100, max_pages=20):
    """Poll ListResourceRequests, paginating up to max_pages of page_size each sweep, until
    our own RequestToken is found. The service gives no positional guarantee for a fresh
    entry, so absence is bounded by exhausting each sweep rather than checking one position."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        next_token = None
        for _ in range(max_pages):
            kwargs = {"MaxResults": page_size}
            if next_token:
                kwargs["NextToken"] = next_token
            listing = cc.list_resource_requests(**kwargs)
            for summary in listing["ResourceRequestStatusSummaries"]:
                if summary["RequestToken"] == token:
                    return summary
            next_token = listing.get("NextToken")
            if not next_token:
                break
        time.sleep(interval_s)
    return None


def _poll_progress(cc, request_token, timeout_s=180.0, interval_s=3.0):
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        r = cc.get_resource_request_status(RequestToken=request_token)
        last = r["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state within {timeout_s}s (last={last})")


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
