"""deploy-cloudwatch-alarm-warm-up-and-evaluation-window-through-update-and-replacement."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-alarm-warm-up-and-evaluation-window-through-update-and-replacement"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudwatch"]

_TERMINAL_STACK_STATUSES = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _poll_stack_status(cf, stack_id: str, *, budget_s: float = 300.0) -> str:
    """Poll DescribeStacks for ``stack_id`` until its status is terminal; return that status."""
    deadline = time.monotonic() + budget_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {budget_s:.0f}s")
        time.sleep(3)


def _destroy_stack(cf, stack_id: str, *, budget_s: float = 300.0) -> None:
    """Delete ``stack_id`` and wait for DELETE_COMPLETE; raise naming the cause otherwise."""
    current = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if current == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = _poll_stack_status(cf, stack_id, budget_s=budget_s)
    assert status == "DELETE_COMPLETE", f"stack {stack_id} delete ended {status!r}"


def _template(alarm_name: str, namespace: str, warm_up: dict, evaluation_window: dict) -> str:
    return json.dumps({
        "Resources": {
            "Alarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": namespace,
                    "MetricName": "ProbeSignal",
                    "Statistic": "Average",
                    "Period": 300,
                    "EvaluationPeriods": 1,
                    "Threshold": 50.0,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "WarmUpConfiguration": warm_up,
                    "EvaluationWindow": evaluation_window,
                },
            },
        },
        "Outputs": {"AlarmRef": {"Value": {"Ref": "Alarm"}}},
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed alarm's WarmUpConfiguration and EvaluationWindow read back through
    DescribeAlarms and both update in place; renaming the alarm (its one createOnly property)
    replaces it with a resource carrying the latest values, which stack deletion then removes.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-warm-up.html
    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/alarm-evaluation-window.html
    """
    cf = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-behav-cwwustk-")
    namespace = ctx.unique_name("Sim2RealBehavWarmUp")
    alarm_name_1 = ctx.unique_name("sim2real-behav-cwwualm1-")
    alarm_name_2 = ctx.unique_name("sim2real-behav-cwwualm2-")

    warm_up_1 = {"WarmUpPeriodDurationInMinutes": 5, "OnlyStartEvaluatingAfterWarmUpPeriodEnds": True}
    window_1 = {"WallClockWindow": {"Timezone": "America/New_York"}}

    stack_id = cf.create_stack(
        StackName=stack_name, TemplateBody=_template(alarm_name_1, namespace, warm_up_1, window_1),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _destroy_stack(cf, stack_id))

    status = _poll_stack_status(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack_name!r} ended {status!r}, not CREATE_COMPLETE"

    alarms = cw.describe_alarms(AlarmNames=[alarm_name_1])["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm named {alarm_name_1!r}, got {alarms!r}"
    alarm = alarms[0]
    assert alarm["WarmUpConfiguration"] == warm_up_1, (
        f"expected WarmUpConfiguration {warm_up_1!r}, got {alarm['WarmUpConfiguration']!r}"
    )
    assert alarm["EvaluationWindow"] == window_1, (
        f"expected EvaluationWindow {window_1!r}, got {alarm['EvaluationWindow']!r}"
    )

    # ---- Update in place: both WarmUpConfiguration fields change; the alarm name does not. ----
    warm_up_2 = {"WarmUpPeriodDurationInMinutes": 10, "OnlyStartEvaluatingAfterWarmUpPeriodEnds": False}
    cf.update_stack(StackName=stack_id, TemplateBody=_template(alarm_name_1, namespace, warm_up_2, window_1))
    status = _poll_stack_status(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"warm-up update ended {status!r}, not UPDATE_COMPLETE"

    alarms = cw.describe_alarms(AlarmNames=[alarm_name_1])["MetricAlarms"]
    assert len(alarms) == 1, f"expected the same alarm {alarm_name_1!r} to survive, got {alarms!r}"
    assert alarms[0]["WarmUpConfiguration"] == warm_up_2, (
        f"expected the updated WarmUpConfiguration {warm_up_2!r}, got {alarms[0]['WarmUpConfiguration']!r}"
    )

    # ---- Update in place: EvaluationWindow switches from a wall clock to a sliding window. ----
    window_2 = {"SlidingWindow": {}}
    cf.update_stack(StackName=stack_id, TemplateBody=_template(alarm_name_1, namespace, warm_up_2, window_2))
    status = _poll_stack_status(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"evaluation window update ended {status!r}, not UPDATE_COMPLETE"

    alarms = cw.describe_alarms(AlarmNames=[alarm_name_1])["MetricAlarms"]
    assert len(alarms) == 1, f"expected the same alarm {alarm_name_1!r} to survive, got {alarms!r}"
    assert alarms[0]["EvaluationWindow"] == window_2, (
        f"expected the updated EvaluationWindow {window_2!r}, got {alarms[0]['EvaluationWindow']!r}"
    )

    # ---- Renaming the alarm (its createOnly property) replaces it. ----
    cf.update_stack(StackName=stack_id, TemplateBody=_template(alarm_name_2, namespace, warm_up_2, window_2))
    status = _poll_stack_status(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"rename update ended {status!r}, not UPDATE_COMPLETE"

    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    assert outputs["AlarmRef"] == alarm_name_2, (
        f"Ref after the rename should be the new name {alarm_name_2!r}, got {outputs['AlarmRef']!r}"
    )

    remaining = cw.describe_alarms(AlarmNames=[alarm_name_1, alarm_name_2])["MetricAlarms"]
    remaining_names = {a["AlarmName"] for a in remaining}
    assert remaining_names == {alarm_name_2}, (
        f"expected only the replacement {alarm_name_2!r} to remain, got {sorted(remaining_names)!r}"
    )
    replacement = remaining[0]
    assert replacement["WarmUpConfiguration"] == warm_up_2, (
        f"the replacement should carry the latest WarmUpConfiguration {warm_up_2!r}, "
        f"got {replacement['WarmUpConfiguration']!r}"
    )
    assert replacement["EvaluationWindow"] == window_2, (
        f"the replacement should carry the latest EvaluationWindow {window_2!r}, "
        f"got {replacement['EvaluationWindow']!r}"
    )

    _destroy_stack(cf, stack_id)
    after_delete = cw.describe_alarms(AlarmNames=[alarm_name_1, alarm_name_2])["MetricAlarms"]
    assert after_delete == [], (
        f"expected no alarm named {alarm_name_1!r} or {alarm_name_2!r} after stack deletion, "
        f"got {after_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
