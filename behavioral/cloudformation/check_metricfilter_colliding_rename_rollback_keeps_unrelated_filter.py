"""metricfilter-colliding-rename-rollback-keeps-unrelated-filter."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metricfilter-colliding-rename-rollback-keeps-unrelated-filter"
GROUP = "deploy-rollback-log-resources"
SERVICES = ["cloudformation"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_MANAGED_PATTERN = "{ $.latency = * }"
_UNRELATED_PATTERN = "UNRELATED"


def _template(group, stream, filter_name, namespace, metric_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {"Type": "AWS::Logs::LogGroup",
                      "DeletionPolicy": "Retain",
                      "Properties": {"LogGroupName": group, "RetentionInDays": 1}},
            "Stream": {"Type": "AWS::Logs::LogStream",
                       "DependsOn": "Group",
                       "Properties": {"LogGroupName": group, "LogStreamName": stream}},
            "Filter": {"Type": "AWS::Logs::MetricFilter",
                       "DependsOn": "Group",
                       "Properties": {
                           "LogGroupName": group,
                           "FilterName": filter_name,
                           "FilterPattern": _MANAGED_PATTERN,
                           "MetricTransformations": [{
                               "MetricName": metric_name, "MetricNamespace": namespace,
                               "MetricValue": "$.latency",
                               "Dimensions": [{"Key": "Route", "Value": "$.route"}],
                           }],
                       }},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:data-plane",
      "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """A FilterName rename colliding with an out-of-band filter rolls back: the managed filter keeps
    its name and still emits metrics, the unrelated filter is never adopted or overwritten, and
    DeleteStack removes only the managed filter.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    cw = ctx.client("cloudwatch")

    group = ctx.unique_name("sim2real-behav-mf-collide-grp-")
    stream = "sim2real-stream"
    namespace = ctx.unique_name("Sim2RealBehavMFCollide/")
    metric_name = "Observed"
    managed_name = ctx.unique_name("sim2real-behav-mf-collide-managed-")
    taken_name = ctx.unique_name("sim2real-behav-mf-collide-taken-")
    stack = ctx.unique_name("sim2real-behav-mf-collide-stack-")
    ctx.on_cleanup(lambda: _delete_log_group_if_present(logs, group))

    created = cfn.create_stack(
        StackName=stack, TemplateBody=_template(group, stream, managed_name, namespace, metric_name),
        OnFailure="ROLLBACK", Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"create ended {status!r}, expected CREATE_COMPLETE"

    # A filter CloudFormation does not own, pre-occupying the name the rename will try to take.
    logs.put_metric_filter(
        logGroupName=group, filterName=taken_name, filterPattern=_UNRELATED_PATTERN,
        metricTransformations=[{"metricName": "Unrelated", "metricNamespace": namespace,
                                 "metricValue": "7"}],
    )
    ctx.on_cleanup(lambda: _delete_filter_if_present(logs, group, taken_name))
    unrelated_before = _describe_filter(logs, group, taken_name)
    assert unrelated_before is not None, "the out-of-band filter did not get created"

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(group, stream, taken_name, namespace, metric_name),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"rename to the colliding name ended {status!r}, expected UPDATE_ROLLBACK_COMPLETE"
    )

    unrelated_after = _describe_filter(logs, group, taken_name)
    assert unrelated_after is not None, "the unrelated filter disappeared after the rollback"
    assert unrelated_after["filterPattern"] == _UNRELATED_PATTERN, (
        f"unrelated filter pattern changed to {unrelated_after['filterPattern']!r}; it must "
        "never be adopted by the stack's replacement attempt"
    )
    assert unrelated_after["creationTime"] == unrelated_before["creationTime"], (
        "the unrelated filter's creationTime changed; it must not have been deleted and recreated"
    )

    managed = _describe_filter(logs, group, managed_name)
    assert managed is not None, f"managed filter {managed_name!r} did not survive the rollback"
    assert managed["filterPattern"] == _MANAGED_PATTERN, (
        f"managed filter pattern is {managed['filterPattern']!r} after the rollback, expected "
        f"{_MANAGED_PATTERN!r}"
    )
    all_filters = logs.describe_metric_filters(logGroupName=group)["metricFilters"]
    assert sorted(f["filterName"] for f in all_filters) == sorted([managed_name, taken_name]), (
        f"expected exactly the managed and unrelated filters, found {all_filters!r}"
    )

    now_ms = int(time.time() * 1000)
    put = logs.put_log_events(
        logGroupName=group, logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": json.dumps({"latency": 4, "route": "/pay"})}],
    )
    assert "rejectedLogEventsInfo" not in put, f"PutLogEvents partially rejected: {put!r}"
    dims = [{"Name": "Route", "Value": "/pay"}]
    total = _poll_sum(cw, namespace, metric_name, dims, 4.0, timeout_s=120.0)
    assert total == 4.0, f"managed filter's metric Sum is {total!r}, expected 4.0"

    cfn.delete_stack(StackName=stack_id)
    del_status = _wait_stack(cfn, stack_id)
    assert del_status == "DELETE_COMPLETE", f"stack delete ended {del_status!r}, expected DELETE_COMPLETE"
    assert _describe_filter(logs, group, managed_name) is None, (
        "the managed filter survived DeleteStack"
    )
    assert _describe_filter(logs, group, taken_name) is not None, (
        "the unrelated filter was deleted by the stack's own teardown"
    )


def _describe_filter(logs, group, name):
    for f in logs.describe_metric_filters(logGroupName=group, filterNamePrefix=name)["metricFilters"]:
        if f["filterName"] == name:
            return f
    return None


def _poll_sum(cw, namespace, metric_name, dims, target, *, timeout_s, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    total = 0.0
    while time.monotonic() < deadline:
        end = datetime.now(timezone.utc) + timedelta(minutes=5)
        start = end - timedelta(minutes=20)
        points = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric_name, Dimensions=dims,
            StartTime=start, EndTime=end, Period=60, Statistics=["Sum"],
        ).get("Datapoints", [])
        total = sum(p.get("Sum", 0.0) for p in points)
        if total >= target:
            return total
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for Sum >= {target!r}; last seen {total!r}")


def _wait_stack(cfn, name, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} did not reach terminal status within {timeout_s}s (last={status})")


def _delete_filter_if_present(logs, group, name):
    try:
        logs.delete_metric_filter(logGroupName=group, filterName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"metric filter {name} in {group}: {exc}") from exc


def _delete_log_group_if_present(logs, name):
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise RuntimeError(f"log group {name}: {exc}") from exc


def _delete_stack(cfn, name):
    try:
        cfn.delete_stack(StackName=name)
        deadline = time.monotonic() + 300.0
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
            except ClientError as err:
                if not (
                    err.response["Error"]["Code"] == "ValidationError"
                    and "does not exist" in err.response["Error"].get("Message", "")
                ):
                    raise
                return
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED":
                raise RuntimeError(f"stack {name} DELETE_FAILED")
            time.sleep(5.0)
        raise RuntimeError(f"stack {name} still deleting after 300s")
    except Exception as exc:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {name}: {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
