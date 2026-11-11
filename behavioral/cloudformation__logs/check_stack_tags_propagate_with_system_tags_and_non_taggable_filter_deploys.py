"""stack-tags-propagate-with-system-tags-and-non-taggable-filter-deploys."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-tags-propagate-with-system-tags-and-non-taggable-filter-deploys"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(log_group_name: str, metric_name: str, metric_namespace: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
            },
            "Filter": {
                "Type": "AWS::Logs::MetricFilter",
                "Properties": {
                    "LogGroupName": {"Ref": "LogGroup"},
                    "FilterPattern": "ERROR",
                    "MetricTransformations": [{
                        "MetricName": metric_name,
                        "MetricNamespace": metric_namespace,
                        "MetricValue": "1",
                    }],
                },
            },
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack-level Tag and all three aws:cloudformation:* system tags propagate to a log group
    (Logs' own ListTagsForResource); a non-taggable AWS::Logs::MetricFilter deploys fine in the
    same stack, and a tags-only UpdateStack changes the log group's tags in place.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    stack = ctx.unique_name("sim2real-xsvc-logstags-")
    log_group_name = ctx.unique_name("sim2real-xsvc-logstags-lg-")
    metric_name = ctx.unique_name("sim2real-xsvc-logstags-metric-")
    metric_namespace = ctx.unique_name("sim2real-xsvc-logstags-ns-")
    template = _template(log_group_name, metric_name, metric_namespace)

    cfn.create_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "v1"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack))
    status = _wait_terminal(cfn, stack)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended in {status!r}, expected CREATE_COMPLETE -- a non-taggable "
        f"AWS::Logs::MetricFilter in the same stack must not block the deploy"
    )

    stack_id = cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackId"]
    group = _log_group(logs, log_group_name)
    log_group_arn = group["logGroupArn"]
    want_tags = {
        "sim2real-env": "v1",
        "aws:cloudformation:stack-name": stack,
        "aws:cloudformation:stack-id": stack_id,
        "aws:cloudformation:logical-id": "LogGroup",
    }
    tag_map = logs.list_tags_for_resource(resourceArn=log_group_arn)["tags"]
    assert tag_map == want_tags, (
        f"expected the stack tag and the three aws:cloudformation:* system tags {want_tags!r} "
        f"on the log group, got {tag_map!r}"
    )

    filter_name = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId="Filter",
    )["StackResourceDetail"]["PhysicalResourceId"]
    filter_before = _metric_filter(logs, log_group_name, filter_name)

    cfn.update_stack(
        StackName=stack, TemplateBody=template,
        Tags=[{"Key": "sim2real-env", "Value": "v2"}],
    )
    status = _wait_terminal(cfn, stack)
    assert status == "UPDATE_COMPLETE", f"stack {stack!r} update ended in {status!r}, expected UPDATE_COMPLETE"

    group_after = _log_group(logs, log_group_name)
    identity = (group["logGroupArn"], group["creationTime"])
    identity_after = (group_after["logGroupArn"], group_after["creationTime"])
    assert identity_after == identity, (
        f"the log group's (ARN, creationTime) changed from {identity!r} to {identity_after!r} "
        f"across a tags-only UpdateStack; it was recreated, not updated in place"
    )
    tag_map_after = logs.list_tags_for_resource(resourceArn=log_group_arn)["tags"]
    want_after = {**want_tags, "sim2real-env": "v2"}
    assert tag_map_after == want_after, (
        f"after the stack tag update, expected {want_after!r} on the same log group, "
        f"got {tag_map_after!r}"
    )

    filter_after = _metric_filter(logs, log_group_name, filter_name)
    assert filter_after == filter_before, (
        f"the non-taggable metric filter should survive a tags-only stack update unchanged; "
        f"before {filter_before!r}, after {filter_after!r}"
    )


def _log_group(logs, log_group_name: str) -> dict:
    """The log group's DescribeLogGroups entry, found by exact name across every page."""
    pages = logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=log_group_name)
    found = [g for page in pages for g in page["logGroups"] if g["logGroupName"] == log_group_name]
    assert len(found) == 1, f"expected one log group named {log_group_name!r}, got {found!r}"
    return found[0]


def _metric_filter(logs, log_group_name: str, filter_name: str) -> dict:
    """The one metric filter named ``filter_name`` on the log group, across every page."""
    pages = logs.get_paginator("describe_metric_filters").paginate(
        logGroupName=log_group_name, filterNamePrefix=filter_name,
    )
    found = [f for page in pages for f in page["metricFilters"] if f["filterName"] == filter_name]
    assert len(found) == 1, f"expected one metric filter named {filter_name!r}, got {found!r}"
    return found[0]


def _wait_terminal(cfn, stack_name: str, *, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a terminal status within {timeout_s}s (last={last!r})")


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
