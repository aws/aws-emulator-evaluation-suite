"""cfn-logs-metricfilter-dimension-unsupported-property-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-metricfilter-dimension-unsupported-property-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}
_VALIDATION_REASON = "Unsupported property [Bogus]"
_VALIDATION_PATH = "/Resources/MF/Properties/MetricTransformations/0/Dimensions/0"


def _template(log_group: str, dimension: dict, *, filter_pattern: str) -> str:
    return json.dumps({
        "Resources": {
            "LG": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": log_group}},
            "MF": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "LG",
                "Properties": {
                    "LogGroupName": log_group,
                    "FilterPattern": filter_pattern,
                    "MetricTransformations": [{
                        "MetricName": "ControlMetric",
                        "MetricNamespace": "sim2real/behav",
                        "MetricValue": "1",
                        "Dimensions": [dimension],
                    }],
                },
            },
        },
    })


def _wait_terminal(cfn, name: str, timeout_s: float = 180.0) -> str:
    """Poll DescribeStacks until the stack reaches a terminal status; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        if last in _TERMINAL:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})")


def _validation_errors(cfn, name: str) -> list[tuple]:
    """``(logical id, reason, path)`` of each VALIDATION_ERROR operation event for MF."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "MF"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _error(fn) -> tuple:
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags(
    "axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control",
)
def run(ctx) -> None:
    """A metric filter's Dimension carrying an undeclared member fails CloudFormation's nested
    additionalProperties pre-provisioning check with its exact message and creates neither the
    filter nor its log group, while a Dimension with only Key and Value deploys and reads back.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    # --- positive control: a Dimension with only the declared members deploys ---
    good_group = ctx.unique_name("sim2real-behav-mfdim-ok-")
    good_stack = ctx.unique_name("sim2real-behav-mfdim-ok-stack-")
    cfn.create_stack(StackName=good_stack, TemplateBody=_template(
        good_group, {"Key": "k1", "Value": "$w1"}, filter_pattern="[w1, w2]"))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    filters = logs.describe_metric_filters(logGroupName=good_group)["metricFilters"]
    assert len(filters) == 1, f"control log group holds {len(filters)} metric filters, expected 1"
    assert filters[0]["filterPattern"] == "[w1, w2]", (
        f"control filter pattern read back as {filters[0]['filterPattern']!r}")
    transform = filters[0]["metricTransformations"][0]
    shown = (transform["metricName"], transform["metricNamespace"], transform["metricValue"])
    assert shown == ("ControlMetric", "sim2real/behav", "1"), (
        f"control metric transformation read back as {shown!r}")
    dims = transform["dimensions"]
    assert dims == {"k1": "$w1"}, f"control filter dimensions read back as {dims!r}"

    # --- negative: the Dimension carries an undeclared member ---
    bad_group = ctx.unique_name("sim2real-behav-mfdim-bad-")
    bad_stack = ctx.unique_name("sim2real-behav-mfdim-bad-stack-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(
            bad_group, {"Key": "k1", "Value": "$w1", "Bogus": "nope"}, filter_pattern="[w1, w2]"),
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"unsupported Dimension member: expected ROLLBACK_COMPLETE, got {status!r}"
    found = _validation_errors(cfn, bad_stack)
    assert found == [("MF", _VALIDATION_REASON, _VALIDATION_PATH)], (
        f"unsupported Dimension member: validation errors expected a single "
        f"({_VALIDATION_REASON!r}, {_VALIDATION_PATH!r}), got {found!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    logical_ids = sorted(r["LogicalResourceId"] for r in resources)
    assert logical_ids == [], (
        f"unsupported Dimension member: a stack rejected before provisioning must list no "
        f"resources, got {logical_ids!r}"
    )
    code, message = _error(lambda: logs.describe_metric_filters(logGroupName=bad_group))
    assert (code, message) == (
        "ResourceNotFoundException", "The specified log group does not exist.",
    ), f"unsupported Dimension member: expected the log group to never exist, got {code!r}: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
