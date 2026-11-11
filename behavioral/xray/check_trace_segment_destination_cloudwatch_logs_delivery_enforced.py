"""trace-segment-destination-cloudwatch-logs-delivery-enforced."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trace-segment-destination-cloudwatch-logs-delivery-enforced"
GROUP = "server-side"
SERVICES = ["xray"]

# The CloudWatch Logs log group Transaction Search delivers ingested spans to.
# See "Prerequisites" in
# https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Enable-TransactionSearch.html
_SPANS_LOG_GROUP = "aws/spans"


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:logs-resource-policy", "resource:account-singleton:xray-trace-segment-destination")
def run(ctx) -> None:
    """Once the trace-segment destination is CloudWatchLogs and ACTIVE, a submitted segment is
    delivered to the aws/spans log group, not merely acknowledged by PutTraceSegments.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Enable-TransactionSearch.html
    """
    xray = ctx.client("xray")
    logs = ctx.client("logs")

    # An update is rejected while a previous switch is still transitioning; wait it out first.
    settled = _settled_trace_segment_destination(xray, timeout_s=600.0)
    current_destination = settled["Destination"]

    # Without this resource policy X-Ray's PutLogEvents into aws/spans is denied, so nothing lands.
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region
    policy_name = "sim2real-xray-transaction-search-policy"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "TransactionSearchXRayAccess",
                "Effect": "Allow",
                "Principal": {"Service": "xray.amazonaws.com"},
                "Action": "logs:PutLogEvents",
                "Resource": [
                    f"arn:aws:logs:{region}:{account}:log-group:aws/spans:*",
                    f"arn:aws:logs:{region}:{account}:log-group:/aws/application-signals/data:*",
                ],
                "Condition": {
                    "ArnLike": {"aws:SourceArn": f"arn:aws:xray:{region}:{account}:*"},
                    "StringEquals": {"aws:SourceAccount": account},
                },
            }
        ],
    }
    logs.put_resource_policy(policyName=policy_name, policyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _safe_delete_resource_policy(logs, policy_name))
    # Registered before the switch (so it runs before the policy delete): the destination is
    # account-wide and must be put back even if anything below fails.
    ctx.on_cleanup(
        lambda: _restore_trace_segment_destination(xray, current_destination, timeout_s=600.0)
    )

    # A switch to the current value is rejected with InvalidRequestException.
    if current_destination != "CloudWatchLogs":
        xray.update_trace_segment_destination(Destination="CloudWatchLogs")

    status_cfg = _settled_trace_segment_destination(xray, timeout_s=600.0)
    assert status_cfg["Status"] == "ACTIVE", f"expected Status=ACTIVE, got {status_cfg['Status']!r}"
    assert status_cfg["Destination"] == "CloudWatchLogs", (
        f"expected Destination=CloudWatchLogs, got {status_cfg['Destination']!r}"
    )

    marker = ctx.unique_name("sim2real-cwl-")
    now = time.time()
    seg = {
        "name": "sim2ray-cwl-svc",
        "id": _hex(16),
        "trace_id": f"1-{int(now):08x}-{_hex(24)}",
        "start_time": now,
        "end_time": now + 0.05,
        "annotations": {"marker": marker},
    }
    resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(seg)])
    unprocessed = resp.get("UnprocessedTraceSegments", [])
    assert unprocessed == [], f"expected no unprocessed segments, got {unprocessed}"

    try:
        found = _poll_until(
            lambda: _search_log_group(logs, _SPANS_LOG_GROUP, marker, now),
            lambda events: len(events) >= 1,
            timeout_s=420,
            interval_s=15,
        )
        assert len(found) >= 1, "segment marker never showed up in the aws/spans log group"
        assert any(marker in e["message"] for e in found), (
            f"marker {marker!r} not found in any matched event message: "
            f"{[e['message'] for e in found]}"
        )
    finally:
        # Restore synchronously so the account is not left mid-transition or pointing at
        # CloudWatchLogs after its delivery policy is deleted.
        _restore_trace_segment_destination(xray, current_destination, timeout_s=600.0)



def _safe_delete_resource_policy(logs, policy_name: str) -> None:
    try:
        logs.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _hex(n: int) -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {last}")
        time.sleep(interval_s)


def _search_log_group(logs, log_group_name: str, marker: str, since_epoch: float):
    try:
        resp = logs.filter_log_events(
            logGroupName=log_group_name,
            filterPattern=f'"{marker}"',
            startTime=int((since_epoch - 60) * 1000),
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return []
        raise
    return resp.get("events", [])


def _settled_trace_segment_destination(xray, *, timeout_s: float) -> dict:
    # AWS refuses UpdateTraceSegmentDestination while a previous switch is still PENDING.
    deadline = time.monotonic() + timeout_s
    while True:
        current = xray.get_trace_segment_destination()
        if current.get("Status") == "ACTIVE":
            return current
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"trace-segment destination still not ACTIVE after {timeout_s}s: {current!r}"
            )
        time.sleep(2)


def _restore_trace_segment_destination(xray, original: str, *, timeout_s: float) -> None:
    """Switch the destination back to `original` and wait until it is ACTIVE again."""
    if _settled_trace_segment_destination(xray, timeout_s=timeout_s)["Destination"] != original:
        xray.update_trace_segment_destination(Destination=original)
        _settled_trace_segment_destination(xray, timeout_s=timeout_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
