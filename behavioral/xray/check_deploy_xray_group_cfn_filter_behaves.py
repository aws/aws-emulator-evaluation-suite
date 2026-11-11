"""deploy-xray-group-cfn-filter-behaves."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "deploy-xray-group-cfn-filter-behaves"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::XRay::Group's FilterExpression, applied to GetTraceSummaries,
    surfaces only the trace segments that match it, not just CREATE_COMPLETE."""
    xray = ctx.client("xray")
    marker = ctx.unique_name("s2rgrp").replace("-", "")
    group_name = ctx.unique_name("sim2real-cfn-grp-")[:32]
    filter_expr = f'annotation.marker = "{marker}"'

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  Group:
    Type: AWS::XRay::Group
    Properties:
      GroupName: "{group_name}"
      FilterExpression: '{filter_expr}'
Outputs:
  GroupARN:
    Value: !GetAtt Group.GroupARN
"""
    outputs = _deploy_cfn(ctx, template)
    assert f"/{group_name}/" in outputs["GroupARN"], (
        f"stack output GroupARN {outputs['GroupARN']!r} does not embed group name {group_name!r}"
    )

    group = xray.get_group(GroupName=group_name)["Group"]
    assert group["FilterExpression"] == filter_expr, (
        f"expected FilterExpression {filter_expr!r}, got {group['FilterExpression']!r}"
    )

    # The trace-segment destination is ACCOUNT-GLOBAL. With Destination=CloudWatchLogs
    # (Transaction Search) PutTraceSegments still accepts both segments, but they land in the
    # aws/spans log group and GetTraceSummaries only sees the indexed fraction -- so the
    # unfiltered poll below sees ZERO traces for its whole budget. Read it (never change it:
    # it is shared) and fail fast with the cause named, instead of a bare 600s timeout.
    destination = xray.get_trace_segment_destination()
    assert (destination.get("Destination"), destination.get("Status")) == ("XRay", "ACTIVE"), (
        "GetTraceSummaries only sees segments when the account's trace segment destination is "
        f"XRay/ACTIVE; it reads {destination.get('Destination')}/{destination.get('Status')}"
    )

    now = time.time()
    match_id = _trace_id()
    miss_id = _trace_id()
    docs = [
        _segment_doc(match_id, "svc-match", now, {"marker": marker}),
        _segment_doc(miss_id, "svc-miss", now, {"marker": marker + "no"}),
    ]
    put_resp = xray.put_trace_segments(TraceSegmentDocuments=docs)
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"put_trace_segments rejected segments: {put_resp.get('UnprocessedTraceSegments')}"
    )

    # A filtered query that only ever polls until *any* result appears cannot tell
    # "the filter correctly excluded miss_id" from "miss_id just isn't indexed yet" --
    # the miss trace's own indexing latency would make the negative pass for free.
    # Prove both traces are ingested and independently visible first, unfiltered,
    # so the later exclusion is attributable to the FilterExpression and not to lag.
    # GetTraceSummaries pages, and the unfiltered window holds every trace any concurrent
    # suite submitted: a first page alone can omit ours (or be empty with a NextToken).
    def _unfiltered_probe():
        return _summary_ids(xray, StartTime=now - 300, EndTime=now + 300, Sampling=False)

    both_ids = _poll_until(
        _unfiltered_probe,
        lambda ids: match_id in ids and miss_id in ids,
        timeout_s=600,
        interval_s=10,
    )
    assert match_id in both_ids and miss_id in both_ids, (
        f"both segments must be independently visible before the filter is meaningful, got {both_ids}"
    )

    def _probe():
        return _summary_ids(
            xray,
            StartTime=now - 300,
            EndTime=now + 300,
            FilterExpression=group["FilterExpression"],
            Sampling=False,
        )

    ids = _poll_until(_probe, lambda ids: match_id in ids, timeout_s=300, interval_s=10)
    assert match_id in ids, f"group FilterExpression excluded the matching trace: {ids}"
    assert miss_id not in ids, f"group FilterExpression let a non-matching trace through: {ids}"


# ===== helpers =====

def _trace_id() -> str:
    return f"1-{int(time.time()):08x}-{uuid.uuid4().hex[:24]}"


def _segment_doc(trace_id: str, name: str, start_time: float, annotations: dict) -> str:
    return json.dumps(
        {
            "trace_id": trace_id,
            "id": uuid.uuid4().hex[:16],
            "name": name,
            "start_time": start_time,
            "end_time": start_time + 0.25,
            "annotations": annotations,
        }
    )


def _summary_ids(xray, max_pages: int = 50, **kwargs) -> set:
    """Every trace id GetTraceSummaries returns for `kwargs`, following NextToken."""
    ids: set = set()
    token = None
    for _ in range(max_pages):
        page = xray.get_trace_summaries(**kwargs, **({"NextToken": token} if token else {}))
        ids.update(s["Id"] for s in page["TraceSummaries"])
        token = page.get("NextToken")
        if not token:
            return ids
    raise AssertionError(f"GetTraceSummaries still paging after {max_pages} pages for {kwargs!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _deploy_cfn(ctx, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-xray-")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: DeleteStack on an already-deleted stack is a no-op and the waiter accepts a
    stack that no longer exists, so any error here is a real teardown failure."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
