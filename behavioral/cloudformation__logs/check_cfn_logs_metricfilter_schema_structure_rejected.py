"""cfn-logs-metricfilter-schema-structure-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-logs-metricfilter-schema-structure-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _template(log_group: str, mf_props: dict) -> str:
    return json.dumps({
        "Resources": {
            "LG": {"Type": "AWS::Logs::LogGroup", "Properties": {"LogGroupName": log_group}},
            "MF": {
                "Type": "AWS::Logs::MetricFilter",
                "DependsOn": "LG",
                "Properties": dict(mf_props, LogGroupName=log_group),
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
    """``(logical id, status, mode, reason, path)`` of each VALIDATION_ERROR operation event for MF."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationStatus"), e.get("ValidationFailureMode"),
             e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "MF"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A metric filter's missing FilterPattern, a missing nested transformation or dimension
    member, and a Dimensions list past its 3-item maximum each fail pre-provisioning property
    validation with the exact reason, and the conforming filter still reads back.
    """
    cfn = ctx.client("cloudformation")
    logs = ctx.client("logs")

    good_group = ctx.unique_name("sim2real-behav-mfschema-ok-")
    good_stack = ctx.unique_name("sim2real-behav-mfschema-ok-stack-")
    good_props = {
        "FilterPattern": "",
        "MetricTransformations": [{
            "MetricName": "ControlMetric", "MetricNamespace": "sim2real/behav", "MetricValue": "1",
        }],
    }
    cfn.create_stack(StackName=good_stack, TemplateBody=_template(good_group, good_props))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    filters = logs.describe_metric_filters(logGroupName=good_group)["metricFilters"]
    names = [f["metricTransformations"][0]["metricName"] for f in filters]
    assert names == ["ControlMetric"], f"control filter did not read back, got {names!r}"

    bad_transform = {"MetricNamespace": "sim2real/behav", "MetricValue": "1"}
    bad_dimension_transform = {
        "MetricName": "BadDim", "MetricNamespace": "sim2real/behav", "MetricValue": "1",
        "Dimensions": [{"Key": "k1"}],
    }
    over_max_transform = {
        "MetricName": "OverMax", "MetricNamespace": "sim2real/behav", "MetricValue": "1",
        "Dimensions": [{"Key": f"k{i}", "Value": f"v{i}"} for i in range(4)],
    }
    cases = [
        ("missing FilterPattern", {"MetricTransformations": [good_props["MetricTransformations"][0]]},
         [("MF", "FAILED", "FAIL", "Required property [FilterPattern] not found", "/Resources/MF/Properties")]),
        ("MetricTransformation missing MetricName", {"FilterPattern": "", "MetricTransformations": [bad_transform]},
         [("MF", "FAILED", "FAIL", "Required property [MetricName] not found",
           "/Resources/MF/Properties/MetricTransformations/0")]),
        ("Dimension missing Value", {"FilterPattern": "", "MetricTransformations": [bad_dimension_transform]},
         [("MF", "FAILED", "FAIL", "Required property [Value] not found",
           "/Resources/MF/Properties/MetricTransformations/0/Dimensions/0")]),
        ("Dimensions above maxItems", {"FilterPattern": "", "MetricTransformations": [over_max_transform]},
         [("MF", "FAILED", "FAIL", "#/MetricTransformations/0/Dimensions: expected maximum item count: 3, found: 4",
           "/Resources/MF/Properties/MetricTransformations/0/Dimensions")]),
    ]
    for label, props, want in cases:
        bad_group = ctx.unique_name(f"sim2real-behav-mfschema-bad-{len(label)}-")
        bad_stack = ctx.unique_name(f"sim2real-behav-mfschema-bad-{len(label)}-stack-")
        cfn.create_stack(StackName=bad_stack, TemplateBody=_template(bad_group, props))
        ctx.on_cleanup(lambda bad_stack=bad_stack: _delete_stack(cfn, bad_stack))
        status = _wait_terminal(cfn, bad_stack)
        assert status == "ROLLBACK_COMPLETE", f"{label}: expected ROLLBACK_COMPLETE, got {status!r}"
        found = _validation_errors(cfn, bad_stack)
        assert found == want, f"{label}: validation errors expected {want!r}, got {found!r}"
        resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
        logical_ids = sorted(r["LogicalResourceId"] for r in resources)
        assert logical_ids == [], (
            f"{label}: a stack rejected before provisioning must list no resources, got {logical_ids!r}"
        )
        got = _error(lambda bad_group=bad_group: logs.describe_metric_filters(logGroupName=bad_group))
        assert got == ("ResourceNotFoundException", "The specified log group does not exist."), (
            f"{label}: DescribeMetricFilters on the never-created log group: {got!r}"
        )

    # Control survives all the rejections above.
    still = logs.describe_metric_filters(logGroupName=good_group)["metricFilters"]
    still_names = [f["metricTransformations"][0]["metricName"] for f in still]
    assert still_names == ["ControlMetric"], f"control filter changed to {still_names!r} after the rejections"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
