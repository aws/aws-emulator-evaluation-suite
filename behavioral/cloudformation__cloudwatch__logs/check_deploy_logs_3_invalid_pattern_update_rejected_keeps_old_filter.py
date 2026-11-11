"""deploy-logs-3-invalid-pattern-update-rejected-keeps-old-filter."""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-logs-3-invalid-pattern-update-rejected-keeps-old-filter"

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
    """Updating a MetricFilter to an invalid FilterPattern rolls back to UPDATE_ROLLBACK_COMPLETE,
    keeping the original filter and group, which still turn JSON log events into the metric.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group = ctx.unique_name("sim2real-xsvc-updlg-")
    stream = "sim2real-stream"
    namespace = ctx.unique_name("sim2real-xsvc-ns-")
    metric = "Latency"
    ctx.on_cleanup(lambda: _delete_log_group_if_present(logs, group))

    stack = ctx.unique_name("sim2real-xsvc-logs3-upd-")
    cfn.create_stack(
        StackName=stack,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=_params(group, stream, _VALID_PATTERN, namespace, metric, 3),
        OnFailure="ROLLBACK",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _wait_stack(cfn, stack, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", f"initial stack ended {status!r}, expected CREATE_COMPLETE"
    filter_id = _physical_id(cfn, stack, "MetricFilter")
    group_id = _physical_id(cfn, stack, "LogGroup")

    # ---- the one broken thing: an invalid FilterPattern on an in-place update ----------------
    cfn.update_stack(
        StackName=stack,
        UsePreviousTemplate=True,
        Parameters=_params(group, stream, _INVALID_PATTERN, namespace, metric, 3),
    )
    status = _wait_stack(cfn, stack, timeout_s=600.0)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"update to FilterPattern {_INVALID_PATTERN!r} ended {status!r}; real AWS fails the "
        "MetricFilter update and rolls back to UPDATE_ROLLBACK_COMPLETE"
    )
    events = _stack_events(cfn, stack)
    failed = [e for e in events
              if e["LogicalResourceId"] == "MetricFilter" and e["ResourceStatus"] == "UPDATE_FAILED"]
    assert failed, (
        "no MetricFilter UPDATE_FAILED event; sequence was "
        f"{[(e['LogicalResourceId'], e['ResourceStatus']) for e in events]!r}"
    )
    reason = failed[0].get("ResourceStatusReason", "")
    # The reason is 'Resource handler returned message: "<msg> (Service: <svc>, Status Code: <n>,
    # Request ID: <uuid>) (SDK Attempt Count: <n>)" (RequestToken: <uuid>, HandlerErrorCode: <code>)'.
    # The uuids and the attempt count vary per run, so each stable part is compared exactly.
    handler_message, _, rest = reason.partition(" (Service: ")
    expected = (
        'Resource handler returned message: "Invalid request provided: AWS::Logs::MetricFilter. '
        "Invalid metric filter pattern"
    )
    assert handler_message == expected, (
        f"MetricFilter UPDATE_FAILED reason {reason!r}; expected the handler message {expected!r}"
    )
    service_and_status = rest.partition(", Request ID: ")[0]
    assert service_and_status == "CloudWatchLogs, Status Code: 400", (
        f"MetricFilter UPDATE_FAILED reason {reason!r}; PutMetricFilter rejects the pattern with HTTP 400"
    )
    handler_code = reason.rpartition(", HandlerErrorCode: ")[2]
    assert handler_code == "InvalidRequest)", (
        f"MetricFilter UPDATE_FAILED reason {reason!r}; the Logs resource handler classifies the "
        "rejected pattern as InvalidRequest"
    )

    # ---- effect absent: the invalid pattern never took hold; nothing was replaced ------------
    assert _physical_id(cfn, stack, "MetricFilter") == filter_id, "the MetricFilter was replaced"
    assert _physical_id(cfn, stack, "LogGroup") == group_id, "the LogGroup was replaced"
    filters = logs.describe_metric_filters(logGroupName=group)["metricFilters"]
    assert [f["filterPattern"] for f in filters] == [_VALID_PATTERN], (
        f"after UPDATE_ROLLBACK_COMPLETE the group's filters are {filters!r}; exactly the "
        f"original {_VALID_PATTERN!r} must remain"
    )
    assert filters[0]["filterName"] == filter_id, (
        f"surviving filter is named {filters[0]['filterName']!r}, expected {filter_id!r}"
    )

    # ---- positive control: the restored filter still produces the dimensioned metric ---------
    now_ms = int(time.time() * 1000)
    put = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": now_ms, "message": json.dumps({"latency": 5, "service": _SERVICE_DIM})},
            {"timestamp": now_ms + 1, "message": json.dumps({"latency": 7, "service": _SERVICE_DIM})},
        ],
    )
    assert "rejectedLogEventsInfo" not in put, f"PutLogEvents partially rejected the batch: {put!r}"
    dims = [{"Name": "Service", "Value": _SERVICE_DIM}]

    def _sum():
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims,
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])
        return sum(p.get("Sum", 0.0) for p in points)

    total = _poll_until(_sum, lambda s: s >= 12.0, timeout_s=300.0, interval_s=10.0,
                        description=f"{namespace}/{metric}{{Service={_SERVICE_DIM}}} Sum to reach 12")
    assert total == 12.0, (
        f"after the rolled-back update the metric Sum is {total!r}; the original filter must "
        "still publish latencies 5 + 7 = 12"
    )


def _params(group, stream, pattern, namespace, metric, retention):
    values = {"GroupName": group, "StreamName": stream, "Pattern": pattern,
              "Namespace": namespace, "MetricName": metric, "Retention": str(retention)}
    return [{"ParameterKey": k, "ParameterValue": v} for k, v in values.items()]


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last: {last!r}")


def _stack_status(cfn, name):
    return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]


def _wait_stack(cfn, name, *, timeout_s):
    return _poll_until(lambda: _stack_status(cfn, name),
                       lambda s: not s.endswith("_IN_PROGRESS"),
                       timeout_s=timeout_s, interval_s=5.0,
                       description=f"stack {name} to leave *_IN_PROGRESS")


def _stack_events(cfn, name):
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=name):
        out.extend(page["StackEvents"])
    return sorted(out, key=lambda e: e["Timestamp"])


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


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
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
            time.sleep(5.0)
        raise RuntimeError(f"stack {name} still deleting after 600s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {name}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
