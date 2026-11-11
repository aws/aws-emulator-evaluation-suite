"""list-resource-requests-resource-type-filter-preserves-order."""
from __future__ import annotations

import json
import re
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-resource-requests-resource-type-filter-preserves-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Unfiltered ListResourceRequests lists three queue creates and one delete (after which GetResource
    answers ResourceNotFoundException); with Operations=[CREATE] it lists exactly the three creates.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_ListResourceRequests.html
    """
    cc = ctx.client("cloudcontrol")
    teardown = _Teardown()

    create_tokens: list[str] = []
    identifiers: list[str] = []
    for i in range(3):
        name = ctx.unique_name(f"sim2real-cc-filt-{i}-")
        resp = cc.create_resource(
            TypeName="AWS::SQS::Queue",
            DesiredState=json.dumps(
                {"QueueName": name, "Tags": [{"Key": "sim2real", "Value": "true"}]}
            ),
        )
        token = resp["ProgressEvent"]["RequestToken"]
        create_tokens.append(token)
        ctx.on_cleanup(lambda t=token: _cleanup_request(cc, "AWS::SQS::Queue", t, teardown))
        time.sleep(1.1)

    for token in create_tokens:
        pe, _ = _wait_for_request(ctx, token)
        assert pe["OperationStatus"] == "SUCCESS", f"create did not succeed: {pe}"
        identifiers.append(pe["Identifier"])

    # delete the first queue -> injects one DELETE request among the CREATE ones
    delete_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifiers[0])
    delete_token = delete_resp["ProgressEvent"]["RequestToken"]
    del_pe, _ = _wait_for_request(ctx, delete_token)
    assert del_pe["OperationStatus"] == "SUCCESS", f"delete did not succeed: {del_pe}"

    get_code, get_message = _error_code(
        lambda: cc.get_resource(TypeName="AWS::SQS::Queue", Identifier=identifiers[0])
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected GetResource on the deleted queue to raise ResourceNotFoundException, got {get_code!r}"
    )
    expected = _handler_not_found(get_message, _queue_not_found_detail(identifiers[0]))
    assert get_message == expected, f"expected message {expected!r}, got {get_message!r}"

    all_tokens = set(create_tokens) | {delete_token}

    unfiltered = _list_all_requests(ctx)
    unfiltered_order = [s["RequestToken"] for s in unfiltered if s.get("RequestToken") in all_tokens]
    assert set(unfiltered_order) == all_tokens, (
        f"not all requests were found in the unfiltered ListResourceRequests: {unfiltered_order}"
    )

    filtered = _list_all_requests(ctx, operations=["CREATE"])
    filtered_order = [s["RequestToken"] for s in filtered if s.get("RequestToken") in all_tokens]
    assert delete_token not in filtered_order, "Operations=[CREATE] filter leaked a DELETE request"
    assert set(filtered_order) == set(create_tokens), (
        f"CREATE filter did not return exactly the 3 create requests: {filtered_order}"
    )
    # ListResourceRequests documents no ordering, so only membership is graded.


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message", "")
    raise AssertionError(f"expected the deleted resource to be gone, but the read SUCCEEDED and returned {result!r}")


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


def _wait_for_request(ctx: Any, token: str, timeout_s: float = 150.0, interval_s: float = 2.0):
    cc = ctx.client("cloudcontrol")
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    history: list[str] = []
    deadline = time.monotonic() + timeout_s
    last_pe = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=token)
        last_pe = resp["ProgressEvent"]
        history.append(last_pe["OperationStatus"])
        if last_pe["OperationStatus"] in terminal:
            return last_pe, history
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state within {timeout_s}s (history={history})")


def _list_all_requests(ctx: Any, operations=None, statuses=None, max_pages: int = 50, max_results: int = 100):
    cc = ctx.client("cloudcontrol")
    out: list[dict[str, Any]] = []
    next_token = None
    filt: dict[str, Any] = {}
    if operations:
        filt["Operations"] = operations
    if statuses:
        filt["OperationStatuses"] = statuses
    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"MaxResults": max_results}
        if filt:
            kwargs["ResourceRequestStatusFilter"] = filt
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        out.extend(resp.get("ResourceRequestStatusSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return out


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
