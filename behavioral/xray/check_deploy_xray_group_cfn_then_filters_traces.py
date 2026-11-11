"""deploy-xray-group-cfn-then-filters-traces."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "deploy-xray-group-cfn-then-filters-traces"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AWS::XRay::Group deployed via CloudFormation with a FilterExpression
    actually filters matching trace summaries when that expression is applied
    through GetTraceSummaries -- not merely reaches CREATE_COMPLETE.
    """
    cfn = ctx.client("cloudformation")
    xray = ctx.client("xray")

    group_name = ctx.unique_name("sim2real-grp-")[:32]
    marker = ctx.unique_name("keep-")[:24]
    filter_expression = f'annotation.marker = "{marker}"'
    stack_name = ctx.unique_name("sim2ray-xray-group-")

    template = json.dumps(
        {
            "Resources": {
                "Group": {
                    "Type": "AWS::XRay::Group",
                    "Properties": {
                        "GroupName": group_name,
                        "FilterExpression": filter_expression,
                    },
                }
            },
            "Outputs": {"GroupArn": {"Value": {"Ref": "Group"}}},
        }
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"),
        timeout_s=180,
        interval_s=5,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", stack.get("StackStatusReason")
    group_arn = next(o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "GroupArn")

    fetched = xray.get_group(GroupARN=group_arn)["Group"]
    assert fetched["GroupName"] == group_name, (
        f"expected group name {group_name!r}, got {fetched['GroupName']!r}"
    )
    assert fetched["FilterExpression"] == filter_expression, (
        f"expected filter expression {filter_expression!r}, got {fetched['FilterExpression']!r}"
    )

    now = time.time()
    matching_trace_id = f"1-{int(now):08x}-{_hex(24)}"
    other_trace_id = f"1-{int(now):08x}-{_hex(24)}"
    matching_seg = {
        "name": "sim2ray-match-svc",
        "id": _hex(16),
        "trace_id": matching_trace_id,
        "start_time": now,
        "end_time": now + 0.05,
        "annotations": {"marker": marker},
    }
    other_seg = {
        "name": "sim2ray-other-svc",
        "id": _hex(16),
        "trace_id": other_trace_id,
        "start_time": now,
        "end_time": now + 0.05,
        "annotations": {"marker": marker + "-nope"},
    }
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=[json.dumps(matching_seg), json.dumps(other_seg)])
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segments were rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    start, end = now - 300, now + 300
    # GetTraceSummaries indexing can lag meaningfully behind ingestion, so
    # poll generously.
    summaries = _poll_until(
        lambda: xray.get_trace_summaries(
            StartTime=start, EndTime=end, FilterExpression=filter_expression, Sampling=False
        )["TraceSummaries"],
        lambda s: len(s) >= 1,
        timeout_s=900,
        interval_s=20,
    )
    ids = {s["Id"] for s in summaries}
    assert matching_trace_id in ids, f"filter expression missed the matching trace: {ids}"
    assert other_trace_id not in ids, f"filter expression let a non-matching trace through: {ids}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
