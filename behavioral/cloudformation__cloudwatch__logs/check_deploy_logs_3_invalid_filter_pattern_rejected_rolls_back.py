"""deploy-logs-3-invalid-filter-pattern-rejected-rolls-back."""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-3-invalid-filter-pattern-rejected-rolls-back"

GROUP = "deploy-rollback-log-resources"

SERVICES = ["cloudformation", "cloudwatch", "logs"]

_INVALID_PATTERN = "{ $.latency = }"
_VALID_PATTERN = "{ $.latency > 0 }"
_SERVICE_DIM = "checkout"

# LogGroup -> LogStream -> MetricFilter, strictly ordered: the MetricFilter is the LAST resource
# CloudFormation provisions, so an invalid pattern fails the stack only after the group and the
# stream already exist, and the rollback has something real to delete.
_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "GroupName": {"Type": "String"},
        "StreamName": {"Type": "String"},
        "Pattern": {"Type": "String"},
        "Namespace": {"Type": "String"},
        "MetricName": {"Type": "String"},
        "Retention": {"Type": "Number"},
    },
    "Resources": {
        "LogGroup": {
            "Type": "AWS::Logs::LogGroup",
            "Properties": {
                "LogGroupName": {"Ref": "GroupName"},
                "RetentionInDays": {"Ref": "Retention"},
            },
        },
        "LogStream": {
            "Type": "AWS::Logs::LogStream",
            "Properties": {
                "LogGroupName": {"Ref": "LogGroup"},
                "LogStreamName": {"Ref": "StreamName"},
            },
        },
        "MetricFilter": {
            "Type": "AWS::Logs::MetricFilter",
            "DependsOn": "LogStream",
            "Properties": {
                "LogGroupName": {"Ref": "LogGroup"},
                "FilterPattern": {"Ref": "Pattern"},
                "MetricTransformations": [
                    {
                        "MetricName": {"Ref": "MetricName"},
                        "MetricNamespace": {"Ref": "Namespace"},
                        "MetricValue": "$.latency",
                        "Dimensions": [{"Key": "Service", "Value": "$.service"}],
                    }
                ],
            },
        },
    },
    "Outputs": {"GroupName": {"Value": {"Ref": "LogGroup"}}},
}


@tags(
    "axis:rejection",
    "concern:deploy",
    "concern:negative-classes",
    "concern:metrics",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An invalid FilterPattern fails the stack and rolls back, deleting the created LogGroup; a valid
    one yields a dimensioned metric, keeps its id on a retention update, and is replaced on rename.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    bad_group = ctx.unique_name("sim2real-xsvc-badlg-")
    good_group = ctx.unique_name("sim2real-xsvc-goodlg-")
    renamed_group = ctx.unique_name("sim2real-xsvc-renamedlg-")
    stream = "sim2real-stream"
    namespace = ctx.unique_name("sim2real-xsvc-ns-")
    metric = "Latency"

    # Safety nets for every group name this check can cause to exist. Registered BEFORE the
    # stacks so LIFO runs them AFTER each stack's own delete.
    for name in (bad_group, good_group, renamed_group):
        ctx.on_cleanup(lambda n=name: _delete_log_group_if_present(logs, n))

    # ---- 1. negative: invalid FilterPattern fails mid-stack and rolls back -------------------
    bad_stack = ctx.unique_name("sim2real-xsvc-logs3-bad-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=_params(bad_group, stream, _INVALID_PATTERN, namespace, metric, 3),
        OnFailure="ROLLBACK",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    bad_status = _wait_stack(cfn, bad_stack, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack with FilterPattern {_INVALID_PATTERN!r} ended {bad_status!r}; real AWS fails "
        "the MetricFilter and rolls back to ROLLBACK_COMPLETE"
    )

    events = _stack_events(cfn, bad_stack)  # oldest first
    seq = {lid: [e["ResourceStatus"] for e in events if e["LogicalResourceId"] == lid]
           for lid in ("LogGroup", "LogStream", "MetricFilter")}
    assert "CREATE_COMPLETE" in seq["LogGroup"] and "DELETE_COMPLETE" in seq["LogGroup"], (
        f"LogGroup event sequence was {seq['LogGroup']!r}; it must be created and then deleted "
        "by the rollback"
    )
    assert seq["LogGroup"].index("CREATE_COMPLETE") < seq["LogGroup"].index("DELETE_COMPLETE"), (
        f"LogGroup was deleted before it was created: {seq['LogGroup']!r}"
    )
    assert "CREATE_COMPLETE" in seq["LogStream"] and "DELETE_COMPLETE" in seq["LogStream"], (
        f"LogStream event sequence was {seq['LogStream']!r}; it must be created then rolled back"
    )
    assert "CREATE_FAILED" in seq["MetricFilter"], (
        f"MetricFilter event sequence was {seq['MetricFilter']!r}; expected CREATE_FAILED"
    )
    failed = [e for e in events
              if e["LogicalResourceId"] == "MetricFilter" and e["ResourceStatus"] == "CREATE_FAILED"]
    reason = failed[0].get("ResourceStatusReason", "")
    handler_code = _reason_field(reason, "HandlerErrorCode")
    assert handler_code == "InvalidRequest", (
        f"MetricFilter CREATE_FAILED reason carried HandlerErrorCode {handler_code!r} (reason "
        f"{reason!r}); the Logs resource handler classifies the rejected pattern as InvalidRequest"
    )
    status_code = _reason_field(reason, "Status Code")
    assert status_code == "400", (
        f"MetricFilter CREATE_FAILED reason carried downstream Status Code {status_code!r} "
        f"(reason {reason!r}); PutMetricFilter rejects the pattern with HTTP 400"
    )
    # The failure happened AFTER the group existed: the group's CREATE_COMPLETE precedes it.
    first_failed_idx = events.index(failed[0])
    group_created_idx = next(i for i, e in enumerate(events)
                             if e["LogicalResourceId"] == "LogGroup"
                             and e["ResourceStatus"] == "CREATE_COMPLETE")
    assert group_created_idx < first_failed_idx, (
        "the MetricFilter failed before the LogGroup was created; the rollback must unwind a "
        f"group that existed (events: {[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r})"
    )
    assert _find_group(logs, bad_group) is None, (
        f"log group {bad_group!r} still exists after ROLLBACK_COMPLETE; the rollback must delete it"
    )
    # The rejected filter never reached the service under the rolled-back group either.
    code, message = _error(lambda: logs.describe_metric_filters(logGroupName=bad_group))
    assert code == "ResourceNotFoundException", (
        f"describe_metric_filters on the rolled-back group did not report it missing: {code!r}"
    )
    assert message == "The specified log group does not exist.", (
        f"describe_metric_filters on the rolled-back group: unexpected message {message!r}"
    )

    # ---- 2. positive control: valid pattern deploys a filter that produces a metric ----------
    good_stack = ctx.unique_name("sim2real-xsvc-logs3-good-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=_params(good_group, stream, _VALID_PATTERN, namespace, metric, 3),
        OnFailure="ROLLBACK",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    good_status = _wait_stack(cfn, good_stack, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack with FilterPattern {_VALID_PATTERN!r} ended {good_status!r}, "
        "expected CREATE_COMPLETE"
    )
    described = _find_group(logs, good_group)
    assert described is not None, f"control log group {good_group!r} is missing after CREATE_COMPLETE"
    assert described.get("retentionInDays") == 3, (
        f"control group retention is {described.get('retentionInDays')!r}, expected 3"
    )
    filters = logs.describe_metric_filters(logGroupName=good_group)["metricFilters"]
    assert len(filters) == 1 and filters[0]["filterPattern"] == _VALID_PATTERN, (
        f"control group metric filters are {filters!r}; expected exactly one with {_VALID_PATTERN!r}"
    )

    now_ms = int(time.time() * 1000)
    put = logs.put_log_events(
        logGroupName=good_group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": now_ms, "message": json.dumps({"latency": 5, "service": _SERVICE_DIM})},
            {"timestamp": now_ms + 1, "message": json.dumps({"latency": 7, "service": _SERVICE_DIM})},
        ],
    )
    assert "rejectedLogEventsInfo" not in put, f"PutLogEvents partially rejected the batch: {put!r}"

    dims = [{"Name": "Service", "Value": _SERVICE_DIM}]

    def _sum(dimensions):
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dimensions,
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])
        return sum(p.get("Sum", 0.0) for p in points)

    total = _poll_until(lambda: _sum(dims), lambda s: s >= 12.0, timeout_s=_budget_s(ctx, 300.0),
                        interval_s=2.0, ctx=ctx,
                        description=f"{namespace}/{metric}{{Service={_SERVICE_DIM}}} Sum to reach 12")
    assert total == 12.0, (
        f"metric Sum under Service={_SERVICE_DIM} is {total!r}; MetricValue $.latency over "
        "latencies 5 and 7 must sum to exactly 12"
    )

    # ---- 3. in-place update: RetentionInDays 3 -> 7 keeps the physical id --------------------
    before_id = _physical_id(cfn, good_stack, "LogGroup")
    assert before_id == good_group, f"LogGroup physical id is {before_id!r}, expected {good_group!r}"
    cfn.update_stack(
        StackName=good_stack,
        UsePreviousTemplate=True,
        Parameters=_params(good_group, stream, _VALID_PATTERN, namespace, metric, 7),
    )
    upd_status = _wait_stack(cfn, good_stack, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert upd_status == "UPDATE_COMPLETE", f"retention update ended {upd_status!r}"
    after_id = _physical_id(cfn, good_stack, "LogGroup")
    assert after_id == before_id, (
        f"RetentionInDays change replaced the LogGroup ({before_id!r} -> {after_id!r}); it is a "
        "mutable property and must update in place"
    )
    described = _find_group(logs, good_group)
    assert described is not None and described.get("retentionInDays") == 7, (
        f"after the update describe_log_groups reports {described!r}; expected retentionInDays 7"
    )
    kept = logs.get_log_events(logGroupName=good_group, logStreamName=stream,
                               startFromHead=True)["events"]
    assert len(kept) == 2, (
        f"the in-place update lost log data: stream holds {len(kept)} event(s), expected 2"
    )

    # ---- 4. replacement: changing LogGroupName creates the new group, deletes the old --------
    cfn.update_stack(
        StackName=good_stack,
        UsePreviousTemplate=True,
        Parameters=_params(renamed_group, stream, _VALID_PATTERN, namespace, metric, 7),
    )
    ren_status = _wait_stack(cfn, good_stack, timeout_s=_budget_s(ctx, 600.0), ctx=ctx)
    assert ren_status == "UPDATE_COMPLETE", f"rename update ended {ren_status!r}"
    new_id = _physical_id(cfn, good_stack, "LogGroup")
    assert new_id == renamed_group, (
        f"after the rename the LogGroup physical id is {new_id!r}, expected {renamed_group!r}"
    )
    renamed = _find_group(logs, renamed_group)
    assert renamed is not None and renamed.get("retentionInDays") == 7, (
        f"renamed group {renamed_group!r} describes as {renamed!r}; expected it present with "
        "retentionInDays 7"
    )
    assert _find_group(logs, good_group) is None, (
        f"old log group {good_group!r} still exists after the replacing update completed"
    )


def _params(group, stream, pattern, namespace, metric, retention):
    values = {"GroupName": group, "StreamName": stream, "Pattern": pattern,
              "Namespace": namespace, "MetricName": metric, "Retention": str(retention)}
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition",
                ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _stack_status(cfn, name):
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _wait_stack(cfn, name, *, timeout_s, ctx=None):
    return _poll_until(lambda: _stack_status(cfn, name),
                       lambda s: not s.endswith("_IN_PROGRESS"),
                       timeout_s=timeout_s, interval_s=1.0,
                       description=f"stack {name} to leave *_IN_PROGRESS", ctx=ctx)


def _stack_events(cfn, name):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page["StackEvents"])
    # DescribeStackEvents lists newest first; reversing keeps the service's order for events
    # that share a Timestamp, which a sort by Timestamp would not.
    return list(reversed(out))


def _physical_id(cfn, stack, logical_id):
    return cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId=logical_id
    )["StackResourceDetail"]["PhysicalResourceId"]


def _find_group(logs, name):
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=name):
        for g in page["logGroups"]:
            if g["logGroupName"] == name:
                return g
    return None


def _reason_field(reason, field):
    """Extract one ``Field: value`` pair from a CloudFormation ResourceStatusReason."""
    m = re.search(re.escape(field) + r":\s*([A-Za-z0-9]+)", reason or "")
    return m.group(1) if m else f"<no {field} in reason>"


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; expected a ClientError")


def _delete_log_group_if_present(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"log group {name}: {exc}") from exc


def _delete_stack(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
        deadline = time.monotonic() + 600.0
        while time.monotonic() < deadline:
            try:
                status = _stack_status(cfn, name)
            except ClientError as exc:
                if "does not exist" in str(exc):
                    return
                raise
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(f"stack {name} DELETE_FAILED")
            time.sleep(1.0)
        raise RuntimeError(f"stack {name} still deleting after 600s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {name}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
