"""cfn-logs-metric-filter-in-place-update-delete-first-replacement-ignores-retain-then-gone."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-metric-filter-in-place-update-delete-first-replacement-ignores-retain-then-gone"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: Logs serves a changed filter within seconds; the cap only stops a hung poll.
_READ_CAP_S = 30.0
#: Every teardown waits to one deadline, set by the first to run, inside the cleanup budget.
_TEARDOWN_S = 1700.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NAMESPACE = "Sim2Real/CfnMetricFilter"
_METRIC = "Matches"
_EVENTS = ["level=ERROR disk full", "level=WARN disk slow", "level=INFO disk ok"]

#: AWS::Logs::MetricFilter replaces delete-then-create (its resource schema's
#: replacementStrategy): CloudFormation deletes the old filter first, whatever UpdateReplacePolicy.
_FILTER_REPLACING = (
    "Requested update requires the replacement of the existing resource; deleting existing "
    "resource, then creating a new one."
)


def _filter_replacement_rows(old_id: str, new_id: str) -> list[tuple]:
    """The (status, reason, physical id) rows of a delete-then-create filter replacement."""
    return [
        ("UPDATE_IN_PROGRESS", None, old_id),
        ("DELETE_IN_PROGRESS", _FILTER_REPLACING, old_id),
        ("DELETE_COMPLETE", f"Resource {old_id} delete complete", old_id),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated", new_id),
        ("CREATE_COMPLETE", None, new_id),
        ("UPDATE_COMPLETE", None, new_id),
    ]


#: Logs' refusal of a log group that does not exist.
_GROUP_NOT_FOUND = "ResourceNotFoundException"


def _template(group: str, filter_name: str, pattern: str, value: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Filter": {
                    "Type": "AWS::Logs::MetricFilter",
                    # FilterName is create-only, so changing it replaces the filter.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "LogGroupName": group,
                        "FilterName": filter_name,
                        "FilterPattern": pattern,
                        "MetricTransformations": [
                            {
                                "MetricNamespace": _NAMESPACE,
                                "MetricName": _METRIC,
                                "MetricValue": value,
                            }
                        ],
                    },
                },
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation metric filter reads back as templated, updates in place, then is replaced.

    TestMetricFilter evaluates the pattern Logs serves; a pattern change keeps the filter, a
    FilterName change deletes the old filter first despite UpdateReplacePolicy Retain.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-metricfilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    group = "/" + ctx.unique_name("sim2real-cfnmf-group-")
    first = ctx.unique_name("sim2real-cfnmf-a-")
    second = ctx.unique_name("sim2real-cfnmf-b-")
    stack_name = ctx.unique_name("sim2real-cfnmf-stack-")
    ref = {"stack": stack_name}
    teardown: dict = {}

    # The log group belongs to the check, so any filter left behind goes with it.
    ctx.on_cleanup(lambda: _delete_group(logs, group))
    logs.create_log_group(logGroupName=group)
    ctx.on_cleanup(lambda: _teardown_stack(ctx, cfn, ref, teardown))

    # ---- 1. create: CloudFormation's view, Logs' view, and the pattern matching
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(group, first, '"level=ERROR"', "1"),
        Tags=_TAGS,
    )["StackId"]
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "CREATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Filter"] == first, (
        f"the filter's physical id must be its FilterName {first!r}"
    )
    _eventually(ctx, _READ_CAP_S, lambda: _assert_filter(logs, group, first, '"level=ERROR"', "1"))
    _assert_matches(logs, group, first, [1])

    # ---- 2. in-place: a new pattern and metric value, the same filter
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(group, first, '"level=WARN"', "2"),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Filter"] == first, (
        "an in-place update keeps the filter"
    )
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Filter"), first, "Filter")
    _eventually(ctx, _READ_CAP_S, lambda: _assert_filter(logs, group, first, '"level=WARN"', "2"))
    _assert_matches(logs, group, first, [2])

    # ---- 3. replacement: delete-then-create removes the old filter even under Retain
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(group, second, '"level=INFO"', "3"),
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Filter"] == second, (
        f"the replacement's physical id must be its FilterName {second!r}"
    )
    _assert_filter_replaced(_rows(_events(cfn, ref["stack"]), seen, "Filter"), first, second)
    _eventually(ctx, _READ_CAP_S, lambda: _assert_filter(logs, group, second, '"level=INFO"', "3"))
    _assert_matches(logs, group, second, [3])
    _assert_names(logs, group, [second])

    # ---- 4. delete: the stack's filter is gone and the group holds no filter
    _delete_stack(ctx, cfn, ref["stack"])
    _eventually(ctx, _READ_CAP_S, lambda: _assert_names(logs, group, []))


def _assert_filter_replaced(rows: list[tuple], old_id: str, new_id: str) -> None:
    """The filter's events delete *old_id* first, then create *new_id*: exactly AWS's rows."""
    want = _filter_replacement_rows(old_id, new_id)
    assert rows == want, f"Filter replacement events {rows!r}, expected {want!r}"


def _filters(logs, group: str) -> list[dict]:
    pages = logs.get_paginator("describe_metric_filters").paginate(logGroupName=group)
    return [f for page in pages for f in page["metricFilters"]]


def _assert_names(logs, group: str, names: list[str]) -> None:
    got = sorted(f["filterName"] for f in _filters(logs, group))
    assert got == names, f"metric filters of {group!r}: {got!r}, expected {names!r}"


def _assert_filter(logs, group: str, name: str, pattern: str, value: str) -> None:
    """DescribeMetricFilters reports the template's filter exactly."""
    found = [f for f in _filters(logs, group) if f["filterName"] == name]
    assert len(found) == 1, f"metric filter {name!r} in {group!r}: {found!r}"
    got = {
        "logGroupName": found[0].get("logGroupName"),
        "filterPattern": found[0].get("filterPattern"),
        "metricTransformations": [
            {k: t.get(k) for k in ("metricNamespace", "metricName", "metricValue")}
            for t in found[0].get("metricTransformations", [])
        ],
    }
    want = {
        "logGroupName": group,
        "filterPattern": pattern,
        "metricTransformations": [
            {"metricNamespace": _NAMESPACE, "metricName": _METRIC, "metricValue": value}
        ],
    }
    assert got == want, f"metric filter {name!r}: {got!r}, expected {want!r}"


def _assert_matches(logs, group: str, name: str, event_numbers: list[int]) -> None:
    """TestMetricFilter, run with the pattern Logs serves for the filter, matches exactly those."""
    (served,) = [f for f in _filters(logs, group) if f["filterName"] == name]
    matches = logs.test_metric_filter(
        filterPattern=served["filterPattern"], logEventMessages=_EVENTS
    )["matches"]
    got = [(m.get("eventNumber"), m.get("eventMessage")) for m in matches]
    want = [(n, _EVENTS[n - 1]) for n in event_numbers]
    assert got == want, (
        f"TestMetricFilter with {served['filterPattern']!r}: {got!r}, expected {want!r}"
    )


def _delete_group(logs, group: str) -> None:
    try:
        logs.delete_log_group(logGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _GROUP_NOT_FOUND:
            raise


def _eventually(ctx, cap_s, probe):
    """Run *probe* until it stops failing an assert; past the cap its last assert fails."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        try:
            return probe()
        except AssertionError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"run budget ended before a read converged: {exc}") from None
                raise
        time.sleep(_POLL_S)


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message.
    """
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status.

    A teardown wait ends at the deadline every teardown shares.
    """
    timeout = _budget_s(ctx, _STACK_CAP_S) if teardown is None else _teardown_left(teardown)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if teardown is None and _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _delete_stack(ctx, cfn, stack_id: str, *, teardown: dict | None = None) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id, teardown=teardown), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict, teardown: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"], teardown=teardown)
    _delete_stack(ctx, cfn, stack["StackId"], teardown=teardown)


def _teardown_left(teardown: dict) -> float:
    """Seconds, at least 1, to the deadline every teardown shares; the first to ask fixes it."""
    deadline = teardown.setdefault("deadline", time.monotonic() + _TEARDOWN_S)
    return max(1.0, deadline - time.monotonic())


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
