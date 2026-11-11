"""cfn-logs-metric-filter-reads-back-and-its-removal-leaves-the-log-group-without-it."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-metric-filter-reads-back-and-its-removal-leaves-the-log-group-without-it"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_DEADLINE_S = 300.0


def _error(fn):
    """Call fn(), which AWS must refuse; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _teardown_stack(cfn, stack_id: str) -> None:
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Logs::MetricFilter reads back its pattern and metric transformation
    through Logs; a stack update that drops it leaves its group with no filter, and the stack
    delete removes the group.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    group = ctx.unique_name("sim2real-cfn-mf-group-")
    filter_name = ctx.unique_name("sim2real-cfn-mf-filter-")
    stack = ctx.unique_name("sim2real-cfn-mf-")
    namespace = ctx.unique_name("Sim2RealBehav/CfnMF/")
    metric_name = "MatchCount"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": group, "RetentionInDays": 1},
            },
            "Filter": {
                "Type": "AWS::Logs::MetricFilter",
                "Properties": {
                    "LogGroupName": {"Ref": "Group"},
                    "FilterName": filter_name,
                    "FilterPattern": "ERROR",
                    "MetricTransformations": [{
                        "MetricName": metric_name,
                        "MetricNamespace": namespace,
                        "MetricValue": "1",
                        "DefaultValue": 0,
                    }],
                },
            },
        },
    }

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack} ended {status}: {_failures(cfn, stack_id)!r}"

    physical_id = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Filter")[
        "StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == filter_name, (
        f"MetricFilter physical id is {physical_id!r}, expected {filter_name!r}")

    described = logs.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name)
    filters = described["metricFilters"]
    assert len(filters) == 1, f"expected exactly one metric filter named {filter_name!r}, got {filters!r}"
    (mf,) = filters
    assert mf["filterPattern"] == "ERROR", f"filterPattern read back as {mf['filterPattern']!r}"
    (transform,) = mf["metricTransformations"]
    assert transform["metricName"] == metric_name, f"metricName read back as {transform['metricName']!r}"
    assert transform["metricNamespace"] == namespace, (
        f"metricNamespace read back as {transform['metricNamespace']!r}")
    assert transform["metricValue"] == "1", f"metricValue read back as {transform['metricValue']!r}"
    assert transform["defaultValue"] == 0, f"defaultValue read back as {transform['defaultValue']!r}"

    # Remove only the filter: the group stays, so the filter's own deletion is observed.
    group_only = {k: v for k, v in template.items()}
    group_only["Resources"] = {"Group": template["Resources"]["Group"]}
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(group_only))
    status = _settle(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack} update ended {status}: {_failures(cfn, stack_id)!r}"
    left = logs.describe_metric_filters(logGroupName=group)["metricFilters"]
    assert left == [], f"the log group still lists metric filters after the removal: {left!r}"

    _teardown_stack(cfn, stack_id)
    code, message = _error(
        lambda: logs.describe_metric_filters(logGroupName=group, filterNamePrefix=filter_name))
    assert code == "ResourceNotFoundException", (
        f"describing metric filters on the deleted group returned {code!r}, "
        f"expected ResourceNotFoundException")
    expected = "The specified log group does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
