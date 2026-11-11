"""cfn-cloudwatch-alarm-nested-required-members-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-cloudwatch-alarm-nested-required-members-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}

_METRIC_STAT = {"Metric": {"Namespace": "sim2real/behav", "MetricName": "ControlMetric"},
                "Period": 300, "Stat": "Average"}


def _template(alarm_name: str, props: dict) -> str:
    full = dict(props)
    full["AlarmName"] = alarm_name
    return json.dumps({"Resources": {"A": {"Type": "AWS::CloudWatch::Alarm", "Properties": full}}})


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
    """``(status, mode, reason, path)`` of each VALIDATION_ERROR operation event for A, sorted."""
    out: list[tuple] = []
    kwargs = {"StackName": name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("ValidationStatus"), e.get("ValidationFailureMode"),
             e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"]
            if e.get("EventType") == "VALIDATION_ERROR" and e.get("LogicalResourceId") == "A"
        )
        if not page.get("NextToken"):
            return sorted(out)
        kwargs["NextToken"] = page["NextToken"]


def _delete_stack(cfn, name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A metric-math alarm whose MetricDataQuery, MetricStat or ActionConfiguration omits a
    required nested member fails pre-provisioning property validation with the exact reason and
    creates no alarm; the conforming alarm deploys.
    """
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    good_name = ctx.unique_name("sim2real-behav-alarmreq-ok-")
    good_stack = ctx.unique_name("sim2real-behav-alarmreq-ok-stack-")
    good_props = {
        "ComparisonOperator": "GreaterThanThreshold", "EvaluationPeriods": 1, "Threshold": 90,
        "Metrics": [{"Id": "m1", "ReturnData": True, "MetricStat": _METRIC_STAT}],
        "ActionConfiguration": {"AlarmTagsPropagation": {"Enabled": True}},
    }
    cfn.create_stack(StackName=good_stack, TemplateBody=_template(good_name, good_props))
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"control stack: expected CREATE_COMPLETE, got {status!r}"
    alarms = cw.describe_alarms(AlarmNames=[good_name])["MetricAlarms"]
    assert [a["AlarmName"] for a in alarms] == [good_name], (
        f"control alarm did not read back, got {alarms!r}"
    )

    missing_id_metrics = [{"ReturnData": True, "MetricStat": _METRIC_STAT}]
    missing_statperiod_metrics = [{
        "Id": "m1", "ReturnData": True,
        "MetricStat": {"Metric": _METRIC_STAT["Metric"]},
    }]
    missing_enabled_action = {"AlarmTagsPropagation": {}}

    cases = [
        ("MetricDataQuery missing Id",
         {"Metrics": missing_id_metrics},
         [("FAILED", "FAIL", "Required property [Id] not found", "/Resources/A/Properties/Metrics/0")]),
        ("MetricStat missing Stat and Period",
         {"Metrics": missing_statperiod_metrics},
         sorted([
             ("FAILED", "FAIL", "Required property [Period] not found",
              "/Resources/A/Properties/Metrics/0/MetricStat"),
             ("FAILED", "FAIL", "Required property [Stat] not found",
              "/Resources/A/Properties/Metrics/0/MetricStat"),
         ])),
        ("ActionConfiguration.AlarmTagsPropagation missing Enabled",
         {"Metrics": [{"Id": "m1", "ReturnData": True, "MetricStat": _METRIC_STAT}],
          "ActionConfiguration": missing_enabled_action},
         [("FAILED", "FAIL", "Required property [Enabled] not found",
           "/Resources/A/Properties/ActionConfiguration/AlarmTagsPropagation")]),
    ]
    for label, override, want in cases:
        bad_name = ctx.unique_name(f"sim2real-behav-alarmreq-bad-{len(label)}-")
        bad_stack = ctx.unique_name(f"sim2real-behav-alarmreq-bad-{len(label)}-stack-")
        full_props = dict(good_props)
        full_props.update(override)
        cfn.create_stack(StackName=bad_stack, TemplateBody=_template(bad_name, full_props))
        ctx.on_cleanup(lambda bad_stack=bad_stack: _delete_stack(cfn, bad_stack))
        status = _wait_terminal(cfn, bad_stack)
        assert status == "ROLLBACK_COMPLETE", f"{label}: expected ROLLBACK_COMPLETE, got {status!r}"
        found = _validation_errors(cfn, bad_stack)
        assert found == want, f"{label}: validation errors expected {want!r}, got {found!r}"
        resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
        assert resources == [], (
            f"{label}: a stack rejected before provisioning must list no resources, got {resources!r}"
        )
        bad_alarms = cw.describe_alarms(AlarmNames=[bad_name])["MetricAlarms"]
        assert bad_alarms == [], f"{label}: expected no alarm created, got {bad_alarms!r}"

    # Control survives all the rejections above.
    still = cw.describe_alarms(AlarmNames=[good_name])["MetricAlarms"]
    assert [a["AlarmName"] for a in still] == [good_name], (
        f"control alarm vanished after the rejections, got {still!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
