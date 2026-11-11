"""resource-request-status-terminal-after-ttl-expiry."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-request-status-terminal-after-ttl-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cloudcontrol"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A request's terminal SUCCESS status stays queryable and unchanged across repeated reads,
    well inside the documented seven-day retention of resource operation requests.

    Reference: https://docs.aws.amazon.com/cloudcontrolapi/latest/APIReference/API_ListResourceRequests.html
    """
    cc = ctx.client("cloudcontrol")
    sqs = ctx.client("sqs")
    queue_name = ctx.unique_name("sim2real-behav-queue-")

    resp = cc.create_resource(
        TypeName="AWS::SQS::Queue",
        DesiredState=json.dumps({
            "QueueName": queue_name,
            "Tags": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real:managed", "Value": "true"}],
        }),
    )
    token = resp["ProgressEvent"]["RequestToken"]
    final = _wait_for_terminal(ctx, cc, token)
    assert final["OperationStatus"] == "SUCCESS", f"create did not reach SUCCESS: {final}"
    identifier = final["Identifier"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=identifier))

    # A terminal status is frozen: consecutive reads return the same SUCCESS event.
    expected = ("SUCCESS", identifier, "CREATE", "AWS::SQS::Queue")
    for _ in range(3):
        event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        seen = (event["OperationStatus"], event.get("Identifier"), event.get("Operation"),
                event.get("TypeName"))
        assert seen == expected, (
            f"terminal status changed on a later read well within the 7-day retention window: "
            f"{seen!r}, expected {expected!r}"
        )

    # The same request is listed under its terminal status.
    listed = _poll(
        ctx,
        lambda: _listed_status(cc, token),
        lambda status: status is not None,
        timeout_s=60.0,
        description=f"ListResourceRequests filtered to SUCCESS lists request {token}",
    )
    assert listed == "SUCCESS", f"ListResourceRequests reports request {token} as {listed!r}"


def _deadline(ctx, seconds: float) -> float:
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else min(seconds, left))


def _poll(ctx, fn, pred, *, timeout_s: float, interval_s: float = 2.0, description: str):
    """Poll fn() until pred() holds; raise with the last observed value at the deadline."""
    deadline = _deadline(ctx, timeout_s)
    while True:
        last = fn()
        if pred(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description}: not met within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _listed_status(cc, token):
    """The OperationStatus ListResourceRequests reports for `token` under a SUCCESS filter."""
    pages = cc.get_paginator("list_resource_requests").paginate(
        ResourceRequestStatusFilter={"Operations": ["CREATE"], "OperationStatuses": ["SUCCESS"]}
    )
    for page in pages:
        for event in page.get("ResourceRequestStatusSummaries", []):
            if event.get("RequestToken") == token:
                return event.get("OperationStatus")
    return None


def _wait_for_terminal(ctx, cc, token, timeout_s: float = 120.0, interval_s: float = 2.0):
    deadline = _deadline(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
        if last["OperationStatus"] in ("SUCCESS", "FAILED", "CANCEL_COMPLETE"):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"request {token} did not reach a terminal state in {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
