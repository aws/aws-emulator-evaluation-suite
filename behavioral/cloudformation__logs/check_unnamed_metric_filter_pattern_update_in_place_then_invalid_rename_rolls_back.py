"""unnamed-metric-filter-pattern-update-in-place-then-invalid-rename-rolls-back."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "unnamed-metric-filter-pattern-update-in-place-then-invalid-rename-rolls-back"
GROUP = "logs-metric-filter-replacement"
SERVICES = ["cloudformation", "logs"]

_STACK_CAP_S = 600.0
_POLL_S = 3.0

_PATTERN_A = '"ERROR"'
_PATTERN_B = '"WARN"'
_INVALID_PATTERN = "{ $.duration = }"
_SAMPLE_EVENTS = ["disk ERROR occurred", "disk WARN detected", "disk OK nominal"]

#: AWS::Logs::MetricFilter replaces by deleting the old filter before creating the new one.
_REPLACING_REASON = (
    "Requested update requires the replacement of the existing resource; deleting existing "
    "resource, then creating a new one."
)

#: The fixed parts of the resource handler's failure reason around the two opaque ids AWS mints.
_REASON_PREFIX = (
    'Resource handler returned message: "Invalid request provided: AWS::Logs::MetricFilter. '
    "Invalid metric filter pattern (Service: CloudWatchLogs, Status Code: 400, Request ID: "
)
_REASON_MIDDLE = ') (SDK Attempt Count: 1)" (RequestToken: '
_REASON_SUFFIX = ", HandlerErrorCode: InvalidRequest)"


def _template(group: str, pattern: str, value: str, *, filter_name: str | None = None) -> str:
    props = {
        "LogGroupName": {"Ref": "Group"},
        "FilterPattern": pattern,
        "MetricTransformations": [
            {"MetricNamespace": "Sim2Real/CfnUnnamedMetricFilter",
             "MetricName": "Matches", "MetricValue": value}
        ],
    }
    if filter_name is not None:
        props["FilterName"] = filter_name
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": group}},
            "Filter": {"Type": "AWS::Logs::MetricFilter", "Properties": props},
        },
    })


def _wait_stack(cfn, stack_id: str, *, cap_s: float = _STACK_CAP_S) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    deadline = time.monotonic() + cap_s
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {cap_s:.0f}s"
            )
        time.sleep(_POLL_S)


def _stack_events(cfn, stack_id: str) -> list[dict]:
    """Every stack event for *stack_id*, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _new_rows(cfn, stack_id: str, seen: set, logical_id: str) -> list[tuple]:
    """(status, reason, physical id) tuples of *logical_id*'s events not already in *seen*."""
    rows = []
    for e in _stack_events(cfn, stack_id):
        if e["EventId"] in seen or e["LogicalResourceId"] != logical_id:
            continue
        seen.add(e["EventId"])
        rows.append((e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId")))
    return rows


def _physical_id(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _filters(logs, group: str) -> list[dict]:
    pages = logs.get_paginator("describe_metric_filters").paginate(logGroupName=group)
    return [f for page in pages for f in page["metricFilters"]]


def _assert_single_filter(logs, group: str, name: str, pattern: str, value: str) -> None:
    found = _filters(logs, group)
    assert [f["filterName"] for f in found] == [name], (
        f"filters of {group!r} are {[f['filterName'] for f in found]!r}, expected only {name!r}"
    )
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
            {"metricNamespace": "Sim2Real/CfnUnnamedMetricFilter", "metricName": "Matches",
             "metricValue": value}
        ],
    }
    assert got == want, f"metric filter {name!r} is {got!r}, expected {want!r}"


def _assert_matches_only(logs, pattern: str, want_message: str) -> None:
    """TestMetricFilter with *pattern* matches exactly the one sample event it names."""
    matches = logs.test_metric_filter(
        filterPattern=pattern, logEventMessages=_SAMPLE_EVENTS
    )["matches"]
    got = [m["eventMessage"] for m in matches]
    assert got == [want_message], (
        f"TestMetricFilter({pattern!r}) matched {got!r}, expected only {want_message!r}"
    )


def _assert_replacement_failure_reason(reason: str) -> None:
    """The handler failure reason is exact except for the two opaque ids AWS mints into it."""
    assert reason.startswith(_REASON_PREFIX), (
        f"failure reason {reason!r} does not start with {_REASON_PREFIX!r}"
    )
    after_prefix = reason[len(_REASON_PREFIX):]
    request_id, sep, after_id = after_prefix.partition(_REASON_MIDDLE)
    assert sep == _REASON_MIDDLE, f"failure reason {reason!r} is missing {_REASON_MIDDLE!r}"
    uuid.UUID(request_id)
    request_token, sep, suffix = after_id.partition(_REASON_SUFFIX)
    assert sep == _REASON_SUFFIX, f"failure reason {reason!r} is missing {_REASON_SUFFIX!r}"
    uuid.UUID(request_token)
    assert suffix == "", f"failure reason {reason!r} has trailing text {suffix!r}"


def _delete_stack(cfn, stack_id: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        if "does not exist" in exc.response["Error"].get("Message", ""):
            return
        raise
    deadline = time.monotonic() + _STACK_CAP_S
    while True:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if "does not exist" in exc.response["Error"].get("Message", ""):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} ended DELETE_FAILED while tearing down")
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {_STACK_CAP_S:.0f}s")
        time.sleep(_POLL_S)


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """An unnamed metric filter updates its pattern and value in place under its generated name;
    a rename together with an invalid pattern fails, and rollback recreates it under a new
    generated name with its pre-rename pattern and value.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group = "/" + ctx.unique_name("sim2real-ummf-group-")
    stack_name = ctx.unique_name("sim2real-ummf-stack-")

    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(group, _PATTERN_A, "1"),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))

    stack = _wait_stack(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"initial create ended {stack['StackStatus']!r}, expected CREATE_COMPLETE"
    )
    generated_name = _physical_id(cfn, stack_id, "Filter")
    _assert_single_filter(logs, group, generated_name, _PATTERN_A, "1")
    _assert_matches_only(logs, _PATTERN_A, "disk ERROR occurred")

    # ---- step 1: pattern and value change in place; the generated name is kept ----------------
    seen = {e["EventId"] for e in _stack_events(cfn, stack_id)}
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(group, _PATTERN_B, "2"))
    stack = _wait_stack(cfn, stack_id)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"in-place update ended {stack['StackStatus']!r}, expected UPDATE_COMPLETE"
    )
    rows = _new_rows(cfn, stack_id, seen, "Filter")
    assert [r[0] for r in rows] == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"pattern/value update produced events {rows!r}, expected a plain in-place update"
    )
    assert _physical_id(cfn, stack_id, "Filter") == generated_name, (
        "an in-place pattern/value update must keep the CloudFormation-generated filter name"
    )
    _assert_single_filter(logs, group, generated_name, _PATTERN_B, "2")
    _assert_matches_only(logs, _PATTERN_B, "disk WARN detected")

    # ---- step 2: the one broken thing — naming the filter with an invalid pattern -------------
    attempted_name = ctx.unique_name("sim2real-ummf-renamed-")
    seen = {e["EventId"] for e in _stack_events(cfn, stack_id)}
    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(group, _INVALID_PATTERN, "3", filter_name=attempted_name),
    )
    stack = _wait_stack(cfn, stack_id)
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"renaming with an invalid pattern ended {stack['StackStatus']!r}, "
        "expected UPDATE_ROLLBACK_COMPLETE"
    )
    rows = _new_rows(cfn, stack_id, seen, "Filter")
    statuses = [r[0] for r in rows]
    want_statuses = [
        "UPDATE_IN_PROGRESS", "DELETE_IN_PROGRESS", "DELETE_COMPLETE",
        "CREATE_IN_PROGRESS", "CREATE_FAILED", "UPDATE_FAILED",
        "UPDATE_IN_PROGRESS", "DELETE_IN_PROGRESS", "DELETE_COMPLETE",
        "CREATE_IN_PROGRESS", "CREATE_COMPLETE", "UPDATE_COMPLETE",
    ]
    assert statuses == want_statuses, (
        f"failed rename produced events {statuses!r}, expected {want_statuses!r}"
    )
    delete_reason = rows[1][1]
    assert delete_reason == _REPLACING_REASON, (
        f"the forward replacement's delete reason is {delete_reason!r}, expected {_REPLACING_REASON!r}"
    )
    failed_reason = rows[5][1]
    _assert_replacement_failure_reason(failed_reason)

    restored_name = _physical_id(cfn, stack_id, "Filter")
    assert restored_name != generated_name, (
        "the rolled-back filter must get a freshly generated name, not the pre-rename one"
    )
    assert restored_name != attempted_name, (
        "the rolled-back filter must not keep the failed replacement's attempted name"
    )
    _assert_single_filter(logs, group, restored_name, _PATTERN_B, "2")
    _assert_matches_only(logs, _PATTERN_B, "disk WARN detected")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
