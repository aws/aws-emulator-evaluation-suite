"""metric-filter-tags-property-rejected-rolls-back-stack."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metric-filter-tags-property-rejected-rolls-back-stack"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(log_group_name: str, metric_name: str, metric_namespace: str, *, filter_tags: bool) -> str:
    filter_props = {
        "LogGroupName": {"Ref": "LogGroup"},
        "FilterPattern": "ERROR",
        "MetricTransformations": [{
            "MetricName": metric_name,
            "MetricNamespace": metric_namespace,
            "MetricValue": "1",
        }],
    }
    if filter_tags:
        filter_props["Tags"] = [{"Key": "sim2real-env", "Value": "x"}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
            },
            "Filter": {"Type": "AWS::Logs::MetricFilter", "Properties": filter_props},
        },
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Tags property on the non-taggable AWS::Logs::MetricFilter fails early property validation
    at /Resources/Filter/Properties/Tags before any resource is touched, so the stack rolls back with
    nothing created; the same template without it deploys and its filter reads back.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-xsvc-mfiltertagrej-")
    log_group_name = ctx.unique_name("sim2real-xsvc-mfiltertagrej-lg-")
    metric_name = ctx.unique_name("sim2real-xsvc-mfiltertagrej-metric-")
    metric_namespace = ctx.unique_name("sim2real-xsvc-mfiltertagrej-ns-")

    bad_template = _template(log_group_name, metric_name, metric_namespace, filter_tags=True)
    cfn.create_stack(StackName=stack, TemplateBody=bad_template)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "ROLLBACK_COMPLETE", (
        f"a Tags property on the non-taggable AWS::Logs::MetricFilter should fail and roll the "
        f"stack back; got {status!r}"
    )
    reason = _stack_failure_reason(cfn, stack)
    want = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
        "issues with resource and property details, resolve each error, then retry the operation."
    )
    assert reason == want, (
        f"expected the stack's CREATE_FAILED reason to be {want!r}, got {reason!r}"
    )
    found = _validation_errors(cfn, stack)
    want_rows = [(
        "Filter", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Unsupported property [Tags]", "/Resources/Filter/Properties/Tags",
    )]
    assert found == want_rows, f"VALIDATION_ERROR rows expected {want_rows!r}, got {found!r}"
    filter_events = [
        e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack)
        for e in page["StackEvents"] if e["LogicalResourceId"] == "Filter"
    ]
    assert filter_events == [], (
        f"the Tags property fails CloudFormation's own early validation before any resource is "
        f"touched, so the Filter resource should carry no stack event at all; got {filter_events!r}"
    )

    groups = _log_group_names(logs, log_group_name)
    assert groups == [], (
        f"the rolled-back stack's log group should not exist afterward, found {groups!r}"
    )

    cfn.delete_stack(StackName=stack)
    _wait_terminal_for_name(cfn, stack)

    good_template = _template(log_group_name, metric_name, metric_namespace, filter_tags=False)
    cfn.create_stack(StackName=stack, TemplateBody=good_template)
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", (
        f"positive control: the same template without the illegal Tags property ended in "
        f"{status!r}, expected CREATE_COMPLETE"
    )
    groups = _log_group_names(logs, log_group_name)
    assert groups == [log_group_name], (
        f"positive control: expected log group [{log_group_name!r}], found {groups!r}"
    )
    filter_name = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId="Filter",
    )["StackResourceDetail"]["PhysicalResourceId"]
    pages = logs.get_paginator("describe_metric_filters").paginate(logGroupName=log_group_name)
    filters = [
        (f["filterName"], f["filterPattern"], f["metricTransformations"][0]["metricName"])
        for page in pages for f in page["metricFilters"]
    ]
    assert filters == [(filter_name, "ERROR", metric_name)], (
        f"positive control: expected the stack's one metric filter {filter_name!r} with pattern "
        f"'ERROR' and metric {metric_name!r}, got {filters!r}"
    )


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, name, status, mode, reason, path)`` of every VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
             e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _log_group_names(logs, prefix: str) -> list[str]:
    pages = logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix)
    return [g["logGroupName"] for page in pages for g in page["logGroups"]]


def _stack_failure_reason(cfn, stack_name: str) -> str | None:
    pages = cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name)
    for e in (e for page in pages for e in page["StackEvents"]):
        if e["LogicalResourceId"] == stack_name and e["ResourceStatus"] == "CREATE_FAILED":
            return e.get("ResourceStatusReason")
    raise AssertionError(f"no stack-level CREATE_FAILED event found for {stack_name!r}")


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


def _wait_terminal_for_name(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name!r} reached DELETE_FAILED while clearing the rollback")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} still present after {timeout_s}s of deleting the rollback")


def _delete_stack_and_wait(cfn, stack_name: str, *, timeout_s: float = 300.0) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise RuntimeError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(5.0)
    raise RuntimeError(f"stack {stack_name} still deleting after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
