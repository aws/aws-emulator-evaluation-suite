"""list-resource-requests-status-filter-preserves-order."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "list-resource-requests-status-filter-preserves-order"
GROUP = "ordering"
SERVICES = ["cloudcontrol"]

_TERMINAL = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
_MAX_PAGES = 50


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Filtering ListResourceRequests by OperationStatuses=['SUCCESS'] returns a
    subset of the unfiltered CREATE list that preserves the same relative order
    of our own requests as the unfiltered call."""
    cc = ctx.client("cloudcontrol")
    ctx.client("sqs")
    ctx.client("sns")

    tokens: list[str] = []
    identifiers: list[tuple[str, str]] = []  # (type_name, identifier)

    for i in range(4):
        if i % 2 == 0:
            name = ctx.unique_name(f"sim2real-behav-cc-flt-sqs-{i}-")
            resp = cc.create_resource(
                TypeName="AWS::SQS::Queue",
                DesiredState=json.dumps({"QueueName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
            )
        else:
            name = ctx.unique_name(f"sim2real-behav-cc-flt-sns-{i}-")
            resp = cc.create_resource(
                TypeName="AWS::SNS::Topic",
                DesiredState=json.dumps({"TopicName": name, "Tags": [{"Key": "sim2real", "Value": CHECK}]}),
            )
        token = resp["ProgressEvent"]["RequestToken"]
        tokens.append(token)
        event = _wait_terminal(ctx, token, timeout_s=90)
        assert event["OperationStatus"] == "SUCCESS", f"setup creation failed: {event}"
        identifiers.append((event["TypeName"], event["Identifier"]))
        time.sleep(0.6)  # keep submissions distinguishable

    def _cleanup_all() -> None:
        # Submit every delete before waiting on any of them: ctx.on_cleanup has its own
        # ~60s budget, and four sequential delete-then-wait rounds routinely exceed it.
        pending = {
            cc.delete_resource(TypeName=type_name, Identifier=identifier)["ProgressEvent"]["RequestToken"]
            for type_name, identifier in identifiers
        }
        deadline = time.monotonic() + 50.0
        while pending and time.monotonic() < deadline:
            for token in list(pending):
                event = cc.get_resource_request_status(RequestToken=token)["ProgressEvent"]
                if event["OperationStatus"] in _TERMINAL:
                    pending.discard(token)
            if pending:
                time.sleep(1.0)

    ctx.on_cleanup(_cleanup_all)

    order_unfiltered = _fetch_ordered_subset(ctx, tokens, operation_statuses=None)
    order_success_only = _fetch_ordered_subset(ctx, tokens, operation_statuses=["SUCCESS"])

    assert len(order_unfiltered) == len(tokens), f"expected {len(tokens)} requests unfiltered, got {len(order_unfiltered)}"
    assert len(order_success_only) == len(tokens), (
        f"expected all {len(tokens)} requests to be SUCCESS-filtered too, got {len(order_success_only)}"
    )
    assert order_unfiltered == order_success_only, (
        f"OperationStatuses filter changed relative order: {order_unfiltered} vs {order_success_only}"
    )


def _fetch_ordered_subset(ctx, tokens: list[str], operation_statuses: list[str] | None) -> list[str]:
    cc = ctx.client("cloudcontrol")
    wanted = set(tokens)
    found: list[str] = []
    next_token = None
    for _ in range(_MAX_PAGES):
        status_filter: dict[str, Any] = {"Operations": ["CREATE"]}
        if operation_statuses:
            status_filter["OperationStatuses"] = operation_statuses
        params: dict[str, Any] = {"MaxResults": 100, "ResourceRequestStatusFilter": status_filter}
        if next_token:
            params["NextToken"] = next_token
        resp = cc.list_resource_requests(**params)
        for summary in resp.get("ResourceRequestStatusSummaries", []):
            if summary["RequestToken"] in wanted and summary["RequestToken"] not in found:
                found.append(summary["RequestToken"])
        next_token = resp.get("NextToken")
        if not next_token or len(found) >= len(tokens):
            break
    return found


def _wait_terminal(ctx, request_token: str, timeout_s: float = 90.0, interval_s: float = 1.0) -> dict:
    cc = ctx.client("cloudcontrol")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        event = cc.get_resource_request_status(RequestToken=request_token)["ProgressEvent"]
        if event["OperationStatus"] in _TERMINAL:
            return event
        time.sleep(interval_s)
    raise AssertionError(f"request {request_token} never reached a terminal status within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
