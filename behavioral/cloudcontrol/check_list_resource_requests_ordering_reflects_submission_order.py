"""list-resource-requests-ordering-reflects-submission-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-resource-requests-ordering-reflects-submission-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Sorting ListResourceRequests entries by EventTime reconstructs the exact submission order
    of three CreateResource calls and a later UpdateResource; raw list order is not asserted."""
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-order-")

    submitted = []  # [(queue_name, request_token), ...] in submission order
    for i in range(3):
        qname = f"{base}{i}"
        resp = cc.create_resource(
            TypeName="AWS::SQS::Queue",
            DesiredState=json.dumps({"QueueName": qname, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
        )
        pe = resp["ProgressEvent"]
        submitted.append((qname, pe["RequestToken"]))
        # Space submissions out so EventTime ordering is unambiguous even at coarse
        # timestamp resolution.
        time.sleep(1.5)

    # A 4th, distinct submission: an UpdateResource on the first queue, issued after all
    # three creates -- it must sort after them by EventTime.
    first_final = _wait_for_terminal(cc, submitted[0][1], timeout_s=120.0)
    assert first_final["OperationStatus"] == "SUCCESS", (
        f"create of {submitted[0][0]} did not succeed: {first_final}"
    )
    identifier0 = first_final["Identifier"]
    update_resp = cc.update_resource(
        TypeName="AWS::SQS::Queue",
        Identifier=identifier0,
        PatchDocument=json.dumps([{"op": "replace", "path": "/DelaySeconds", "value": 3}]),
    )
    submitted.append((None, update_resp["ProgressEvent"]["RequestToken"]))

    def _cleanup():
        for _label, token in submitted:
            try:
                final = _wait_for_terminal(cc, token, timeout_s=60.0)
                identifier = final.get("Identifier")
                if identifier:
                    sqs.delete_queue(QueueUrl=identifier)
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "AWS.SimpleQueueService.NonExistentQueue",
                    "QueueDoesNotExist",
                    "RequestTokenNotFoundException",
                ):
                    raise

    ctx.on_cleanup(_cleanup)

    _wait_for_terminal(cc, submitted[-1][1], timeout_s=120.0)  # let the update settle too

    entries = _list_all_requests(cc)
    submitted_tokens = [s[1] for s in submitted]
    token_to_idx = {tok: i for i, tok in enumerate(submitted_tokens)}
    matched = [e for e in entries if e.get("RequestToken") in token_to_idx]
    assert len(matched) == len(submitted_tokens), (
        f"expected {len(submitted_tokens)} matching entries, found {len(matched)}"
    )

    # Raw list order need not match submission order; only EventTime order is graded.
    matched.sort(key=lambda e: e["EventTime"])
    eventtime_order = [token_to_idx[e["RequestToken"]] for e in matched]
    assert eventtime_order == list(range(len(submitted_tokens))), (
        f"EventTime order {eventtime_order} does not reconstruct submission order"
    )


def _wait_for_terminal(cc, token, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


def _list_all_requests(cc, max_pages: int = 10):
    entries = []
    next_token = None
    for _ in range(max_pages):
        kwargs = {"ResourceRequestStatusFilter": {"Operations": ["CREATE", "UPDATE"]}, "MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        resp = cc.list_resource_requests(**kwargs)
        entries.extend(resp.get("ResourceRequestStatusSummaries", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return entries


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

