"""cfn-metric-filter-name-string-constraints-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-metric-filter-name-string-constraints-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}
_FILTER_NAME_PATH = "/Resources/R/Properties/FilterName"
_FILTER_NAME_PATTERN = "^[^:*]{1,512}"
# Only the per-request ids and the SDK attempt count are masked; every other character is compared.
_REQUEST_IDS = re.compile(r"(Request ID: |RequestToken: )[0-9A-Za-z-]+")
_ATTEMPTS = re.compile(r"(SDK Attempt Count: )[0-9]+")
_PATTERN_REASON = (
    'Resource handler returned message: "Invalid request provided: AWS::Logs::MetricFilter. '
    "1 validation error detected: Value at 'filterNamePrefix' failed to satisfy constraint: "
    "Member must satisfy regular expression pattern: [^:*]* (Service: CloudWatchLogs, "
    'Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)" (RequestToken: <id>, HandlerErrorCode: InvalidRequest)'
)


def _template(filter_name: str, log_group_name: str) -> str:
    return json.dumps({
        "Resources": {
            "R": {
                "Type": "AWS::Logs::MetricFilter",
                "Properties": {
                    "FilterName": filter_name,
                    "LogGroupName": log_group_name,
                    "FilterPattern": "",
                    "MetricTransformations": [
                        {"MetricValue": "1", "MetricName": "sim2real-behav-mf-metric",
                         "MetricNamespace": "sim2real-behav-mf-ns"},
                    ],
                },
            },
        },
    })


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 180.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal state within "
                          f"{timeout_s}s (last={last!r})")


def _validation_reasons(cfn, stack_name: str, path: str) -> list[str]:
    """Every VALIDATION_ERROR reason CloudFormation recorded for one property path."""
    out: list[str] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            e["ValidationStatusReason"] for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("ValidationPath") == path
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _resource_failure_reason(cfn, stack_name: str, logical_id: str) -> str:
    """The *_FAILED event's own reason for one logical id."""
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
        for event in page["StackEvents"]:
            if (
                event.get("LogicalResourceId") == logical_id
                and event.get("ResourceStatus", "").endswith("_FAILED")
                and event.get("ResourceStatusReason")
            ):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no *_FAILED event with a reason found for logical id {logical_id!r}")


def _poll_delete(cfn, stack_name: str, timeout_s: float) -> str | None:
    """The stack's terminal status, or None if it vanished outright (never provisioned anything,
    so DescribeStacks reports it as a ValidationError rather than DELETE_COMPLETE)."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                return None
            raise
        if status in _TERMINAL_STATES:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach a terminal delete state within "
                          f"{timeout_s}s (last={status!r})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 180.0) -> None:
    """A MetricFilter delete handler re-validates the template's own invalid property value for a
    resource that was never created and fails identically forever; AWS allows RetainResources
    only on a retry of a stack already in DELETE_FAILED.
    """
    cfn.delete_stack(StackName=stack_name)
    status = _poll_delete(cfn, stack_name, timeout_s)
    if status is None:
        return
    if status == "DELETE_FAILED":
        resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
        retain = [r["LogicalResourceId"] for r in resources
                  if r["ResourceStatus"] in ("CREATE_FAILED", "DELETE_FAILED")]
        cfn.delete_stack(StackName=stack_name, RetainResources=retain)
        status = _poll_delete(cfn, stack_name, timeout_s)
        if status is None:
            return
    assert status == "DELETE_COMPLETE", f"stack {stack_name} failed to delete: {status!r}"


def _metric_filter_names(logs, log_group: str) -> list[str]:
    """Every metric filter name on ``log_group``, paginated."""
    names: list[str] = []
    for page in logs.get_paginator("describe_metric_filters").paginate(logGroupName=log_group):
        names.extend(f["filterName"] for f in page["metricFilters"])
    return names


def _masked(reason: str) -> str:
    return _ATTEMPTS.sub(r"\1<n>", _REQUEST_IDS.sub(r"\1<id>", reason))


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A FilterName over maxLength or under minLength fails CloudFormation's property validation,
    and one with a colon (which the schema's unanchored pattern accepts) fails CloudWatch Logs'
    handler validation; none creates a filter, and a legal name deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-logs-metricfilter.html
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")
    log_group = ctx.unique_name("sim2real-behav-mf-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))
    valid_filter = ctx.unique_name("sim2real-behav-mf-")

    # --- positive control: a legal FilterName deploys ------------------------------------------
    stack_ok = ctx.unique_name("sim2real-behav-mf-ok-stack-")
    cfn.create_stack(StackName=stack_ok, TemplateBody=_template(valid_filter, log_group))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_ok))
    status = _wait_terminal(cfn, stack_ok)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    names = _metric_filter_names(logs, log_group)
    assert names == [valid_filter], f"control metric filter: expected [{valid_filter!r}], got {names!r}"

    # --- pattern violation: CloudFormation's unanchored FilterName pattern accepts the colon, so
    # the refusal is CloudWatch Logs' own handler validation ---------------------------------
    pattern_name = f"{valid_filter}:invalid"
    stack_pattern = ctx.unique_name("sim2real-behav-mf-pat-stack-")
    cfn.create_stack(StackName=stack_pattern, TemplateBody=_template(pattern_name, log_group),
                      DisableRollback=True)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_pattern))
    status = _wait_terminal(cfn, stack_pattern)
    assert status == "CREATE_FAILED", f"pattern violation: expected CREATE_FAILED, got {status!r}"
    reason = _resource_failure_reason(cfn, stack_pattern, "R")
    assert _masked(reason) == _PATTERN_REASON, f"pattern violation reason: {reason!r}"

    # --- maxLength violation: one character past the 512-character ceiling ---------------------
    maxlen_name = valid_filter + "a" * (513 - len(valid_filter))
    assert len(maxlen_name) == 513, maxlen_name
    stack_maxlen = ctx.unique_name("sim2real-behav-mf-maxlen-stack-")
    cfn.create_stack(StackName=stack_maxlen, TemplateBody=_template(maxlen_name, log_group),
                      DisableRollback=True)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_maxlen))
    status = _wait_terminal(cfn, stack_maxlen)
    assert status == "CREATE_FAILED", f"maxLength violation: expected CREATE_FAILED, got {status!r}"
    reasons = _validation_reasons(cfn, stack_maxlen, _FILTER_NAME_PATH)
    assert reasons == ["#/FilterName: expected maxLength: 512, actual: 513"], (
        f"maxLength violation reasons: {reasons!r}"
    )

    # --- minLength violation: the empty string satisfies no character class either --------------
    stack_minlen = ctx.unique_name("sim2real-behav-mf-minlen-stack-")
    cfn.create_stack(StackName=stack_minlen, TemplateBody=_template("", log_group),
                      DisableRollback=True)
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_minlen))
    status = _wait_terminal(cfn, stack_minlen)
    assert status == "CREATE_FAILED", f"minLength violation: expected CREATE_FAILED, got {status!r}"
    reasons = sorted(_validation_reasons(cfn, stack_minlen, _FILTER_NAME_PATH))
    want = sorted([
        "#/FilterName: expected minLength: 1, actual: 0",
        f"Property value [] does not match pattern: {_FILTER_NAME_PATTERN}",
    ])
    assert reasons == want, f"minLength violation reasons: {reasons!r}"

    # --- effect absent: the log group holds only the control's filter -------------------------
    names = _metric_filter_names(logs, log_group)
    assert names == [valid_filter], f"refused creates left metric filters behind: {names!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
