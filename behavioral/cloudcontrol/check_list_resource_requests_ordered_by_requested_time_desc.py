"""list-resource-requests-ordered-by-requested-time-desc."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-ordered-by-requested-time-desc"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListResourceRequests reports EventTimes for create(A), create(B), delete(A) that order
    most-recent-first; list position itself is not asserted."""
    cc = ctx.client("cloudcontrol")
    name_a = ctx.unique_name("sim2real-cc-ord-a-")
    name_b = ctx.unique_name("sim2real-cc-ord-b-")

    queue_a = _create_queue(ctx, cc, name_a)
    queue_b = _create_queue(ctx, cc, name_b)

    # Delete A last, so the chronological order (most-recent-first) is:
    # delete(A), create(B), create(A).
    del_resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=queue_a["identifier"])
    del_token = del_resp["ProgressEvent"]["RequestToken"]
    del_final = _poll_progress(cc, del_token)
    assert del_final["OperationStatus"] == "SUCCESS", f"delete of queue A failed: {del_final}"

    # The listing can include unrelated requests in the account, and list position does not
    # reliably run most-recent-first even among these three, so only EventTime is compared.
    our_tokens = {del_token, queue_b["create_request_token"], queue_a["create_request_token"]}
    listing = cc.list_resource_requests(MaxResults=100)
    summaries = listing["ResourceRequestStatusSummaries"]
    times = {s["RequestToken"]: s["EventTime"] for s in summaries if s["RequestToken"] in our_tokens}
    assert len(times) == 3, f"expected all 3 of our requests visible in the listing, got {times}"

    ordered_times = [times[del_token], times[queue_b["create_request_token"]], times[queue_a["create_request_token"]]]
    assert ordered_times == sorted(ordered_times, reverse=True), (
        f"expected our own tracked requests' EventTime to run delete(A) > create(B) > create(A) "
        f"(most-recent-first), got {ordered_times}"
    )


def _poll_progress(cc, request_token, timeout_s=180.0, interval_s=3.0):
    """Poll GetResourceRequestStatus until the request reaches a terminal OperationStatus."""
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cc.get_resource_request_status(RequestToken=request_token)
        last = resp["ProgressEvent"]
        if last["OperationStatus"] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} did not reach a terminal state within {timeout_s}s (last={last})")


def _delete_queue_quiet(cc, identifier):
    try:
        resp = cc.delete_resource(TypeName="AWS::SQS::Queue", Identifier=identifier)
        _poll_progress(cc, resp["ProgressEvent"]["RequestToken"], timeout_s=60.0, interval_s=2.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "RequestTokenNotFoundException",
            "ResourceNotFoundException",
            "TypeNotFoundException",
        ):
            raise


def _create_queue(ctx, cc, name):
    """Submit CreateResource for an SQS queue, wait for SUCCESS, register delete cleanup."""
    desired = json.dumps({"QueueName": name})
    resp = cc.create_resource(TypeName="AWS::SQS::Queue", DesiredState=desired)
    request_token = resp["ProgressEvent"]["RequestToken"]
    final = _poll_progress(cc, request_token)
    if final["OperationStatus"] != "SUCCESS":
        raise AssertionError(f"create queue {name} did not succeed: {final}")
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda ident=identifier: _delete_queue_quiet(cc, ident))
    return {"identifier": identifier, "create_request_token": request_token}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
