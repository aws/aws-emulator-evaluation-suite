"""deploy-group-via-cloudformation-filters-traces."""
from __future__ import annotations

import json
import random
import time

from behavioral_harness import tags

CHECK = "deploy-group-via-cloudformation-filters-traces"
GROUP = "deploy"
SERVICES = ["xray"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:metrics", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::XRay::Group with a FilterExpression actually
    scopes GetTraceSummaries: a trace matching the expression is returned when
    querying with GroupName, a non-matching trace ingested in the same window is not."""
    xray = ctx.client("xray")
    # AWS::XRay::Group GroupName is capped at 32 chars by CloudFormation; ctx.unique_name
    # appends a 12-hex-char suffix, so the prefix itself must stay <= 20 chars.
    group_name = ctx.unique_name("sim2real-grp-")
    marker = ctx.unique_name("xraymark-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TraceGroup": {
                "Type": "AWS::XRay::Group",
                "Properties": {
                    "GroupName": group_name,
                    "FilterExpression": f'annotation.scenario = "{marker}"',
                },
            }
        },
    }
    _deploy_cfn_stack(ctx, template)

    group = xray.get_group(GroupName=group_name)["Group"]
    assert group["FilterExpression"] == f'annotation.scenario = "{marker}"', (
        f"CFN-deployed group {group_name!r} must expose the FilterExpression from its "
        f"template, got {group['FilterExpression']!r}"
    )

    now = time.time()
    match_trace_id = _make_trace_id()
    nomatch_trace_id = _make_trace_id()
    svc_name = ctx.unique_name("sim2real-xray-svc-")
    match_seg = {
        "trace_id": match_trace_id,
        "id": _make_segment_id(),
        "name": svc_name,
        "start_time": now - 5,
        "end_time": now - 1,
        "annotations": {"scenario": marker},
    }
    nomatch_seg = {
        "trace_id": nomatch_trace_id,
        "id": _make_segment_id(),
        "name": svc_name,
        "start_time": now - 5,
        "end_time": now - 1,
        "annotations": {"scenario": marker + "-nomatch"},
    }
    put_resp = xray.put_trace_segments(
        TraceSegmentDocuments=[json.dumps(match_seg), json.dumps(nomatch_seg)]
    )
    assert put_resp.get("UnprocessedTraceSegments", []) == [], (
        f"segments were rejected: {put_resp.get('UnprocessedTraceSegments')}"
    )

    window_start = now - 600
    window_end = now + 600

    # Baseline: confirm both traces actually got ingested (a plain time-window query,
    # with no filter, which does not depend on annotation/service indexing latency), so
    # the later absence of the non-matching trace is due to the group filter and
    # not a failed PutTraceSegments.
    both_ids = _poll_until(
        lambda: {
            s["Id"]
            for s in xray.get_trace_summaries(
                StartTime=window_start,
                EndTime=window_end,
            )["TraceSummaries"]
        },
        lambda ids: match_trace_id in ids and nomatch_trace_id in ids,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert match_trace_id in both_ids and nomatch_trace_id in both_ids, (
        f"both traces must be indexed by the unfiltered baseline query before the group-scoped "
        f"query is judged, or exclusion below cannot be told apart from not-yet-ingested: "
        f"match={match_trace_id in both_ids} nomatch={nomatch_trace_id in both_ids} ids={sorted(both_ids)!r}"
    )

    grouped_ids = _poll_until(
        lambda: {
            s["Id"]
            for s in xray.get_trace_summaries(
                StartTime=window_start,
                EndTime=window_end,
                FilterExpression=f'group.name = "{group_name}"',
            )["TraceSummaries"]
        },
        lambda ids: match_trace_id in ids,
        timeout_s=300.0,
        interval_s=10.0,
    )
    assert match_trace_id in grouped_ids, "group-scoped query excluded the matching trace"
    assert nomatch_trace_id not in grouped_ids, (
        "group-scoped query included a trace that does not satisfy the group's FilterExpression"
    )


def _deploy_cfn_stack(ctx, template: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-xray-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 200})
    return stack_name


def _make_trace_id() -> str:
    epoch = format(int(time.time()), "x")[-8:].rjust(8, "0")
    rand = "".join(random.choice("0123456789abcdef") for _ in range(24))
    return f"1-{epoch}-{rand}"


def _make_segment_id() -> str:
    return "".join(random.choice("0123456789abcdef") for _ in range(16))


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
