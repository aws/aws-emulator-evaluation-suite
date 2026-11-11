"""list-resource-requests-honors-status-filter."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-requests-honors-status-filter"
GROUP = "representation"
SERVICES = ["cloudcontrol"]

_SNS_TOPIC = "AWS::SNS::Topic"
_MAX_PAGES = 50


def _error_code(fn):
    """The AWS error code and message raised by fn(). Raises if the call unexpectedly succeeds, so
    a target that serves what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"the call was expected to fail but returned {result!r}")


def _sns_topic_not_found(message):
    """The SNS handler's NotFound text; its request ids and attempt count vary per call, so they are read back."""
    found = re.search(r"Request ID: ([^)]*)\) \(SDK Attempt Count: (\d+)\) .*RequestToken: ([^)]*)\)$", message)
    request_id, attempts, token = found.groups() if found else ("<id>", "<n>", "<token>")
    return (
        "AWS::SNS::Topic Handler returned status FAILED: Topic does not exist (Service: Sns, Status Code: 404, "
        f"Request ID: {request_id}) (SDK Attempt Count: {attempts}) (HandlerErrorCode: NotFound, RequestToken: {token})"
    )


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests with a CREATE/SUCCESS filter lists this check's successful topic create and
    only matching rows, a DELETE/FAILED filter excludes it, and after the delete GetResource answers
    ResourceNotFoundException."""
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()
    name = ctx.unique_name("sim2real-behav-cc-topic-")
    final = _create_and_wait(
        ctx, cc, _SNS_TOPIC, {"TopicName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}, teardown=teardown
    )
    assert final["OperationStatus"] == "SUCCESS", final
    token = final["RequestToken"]

    def summaries(status_filter):
        out = []
        kwargs = {"ResourceRequestStatusFilter": status_filter}
        for _ in range(_MAX_PAGES):
            resp = cc.list_resource_requests(**kwargs)
            out.extend(resp.get("ResourceRequestStatusSummaries", []))
            next_token = resp.get("NextToken")
            if not next_token:
                break
            kwargs["NextToken"] = next_token
        else:
            raise AssertionError(f"list_resource_requests did not terminate within {_MAX_PAGES} pages")
        return out

    matching = _poll_until(
        lambda: summaries({"Operations": ["CREATE"], "OperationStatuses": ["SUCCESS"]}),
        lambda rows: any(r["RequestToken"] == token for r in rows),
        timeout_s=60,
        interval_s=3,
        description="our successful CREATE to appear under the CREATE/SUCCESS filter",
    )
    # Every returned row must actually satisfy the filter.
    for row in matching:
        assert row["Operation"] == "CREATE", row
        assert row["OperationStatus"] == "SUCCESS", row

    # A filter that cannot match our successful CREATE must exclude it.
    excluded = summaries({"Operations": ["DELETE"], "OperationStatuses": ["FAILED"]})
    for row in excluded:
        assert row["Operation"] == "DELETE", row
        assert row["OperationStatus"] == "FAILED", row
    assert token not in {r["RequestToken"] for r in excluded}, excluded

    delete_event = _delete_and_wait(cc, _SNS_TOPIC, final["Identifier"])
    assert delete_event["OperationStatus"] == "SUCCESS", delete_event
    not_found_code, not_found_message = _error_code(
        lambda: cc.get_resource(TypeName=_SNS_TOPIC, Identifier=final["Identifier"])
    )
    assert not_found_code == "ResourceNotFoundException", not_found_code
    expected = _sns_topic_not_found(not_found_message)
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


_TERMINAL_STATUSES = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _wait_for_request(cc, request_token: str, timeout_s: float = 60, interval_s: float = 2) -> dict:
    """Poll GetResourceRequestStatus until a terminal OperationStatus is reached."""

    def probe():
        return cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]

    return _poll_until(
        probe,
        lambda ev: ev.get("OperationStatus") in _TERMINAL_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"request {request_token} to reach a terminal state",
    )


def _create_and_wait(ctx, cc, type_name: str, desired_state: dict, timeout_s: float = 60, *, teardown) -> dict:
    """CreateResource + poll to terminal; registers teardown for a successful create."""
    resp = cc.create_resource(TypeName=type_name, DesiredState=json.dumps(desired_state))
    final = _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)
    if final.get("OperationStatus") == "SUCCESS" and final.get("Identifier"):
        identifier = final["Identifier"]
        ctx.on_cleanup(lambda: _delete_resource(cc, type_name, identifier, teardown))
    return final


def _delete_and_wait(cc, type_name: str, identifier: str, timeout_s: float = 60) -> dict:
    resp = cc.delete_resource(TypeName=type_name, Identifier=identifier)
    return _wait_for_request(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=timeout_s)


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
