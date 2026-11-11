"""describe-alarms-for-metric-reflects-actions-enabled-toggle-immediately."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarms-for-metric-reflects-actions-enabled-toggle-immediately"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmsForMetric's ActionsEnabled flag reflects the outcome of
    Disable/EnableAlarmActions on the very next call -- no stale cached view."""
    cw = ctx.client("cloudwatch")

    alarm_name = ctx.unique_name("sim2real-behav-actionsalarm-")
    namespace = "Sim2RealBehavioral"
    metric_name = ctx.unique_name("ActionsToggleMetric-")
    common = dict(
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
    )

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        **common,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    after_create = _actions_enabled(cw, alarm_name, common)
    assert after_create is True, f"expected ActionsEnabled=True right after create, got {after_create!r}"

    cw.disable_alarm_actions(AlarmNames=[alarm_name])
    after_disable = _actions_enabled(cw, alarm_name, common)
    assert after_disable is False, f"expected ActionsEnabled=False on the very next call after DisableAlarmActions, got {after_disable!r}"

    cw.enable_alarm_actions(AlarmNames=[alarm_name])
    after_enable = _actions_enabled(cw, alarm_name, common)
    assert after_enable is True, f"expected ActionsEnabled=True on the very next call after EnableAlarmActions, got {after_enable!r}"


def _actions_enabled(cw, alarm_name: str, common: dict) -> bool:
    resp = cw.describe_alarms_for_metric(**common)
    matches = [a for a in resp["MetricAlarms"] if a["AlarmName"] == alarm_name]
    assert len(matches) == 1, (
        f"expected exactly one alarm named {alarm_name} in DescribeAlarmsForMetric, "
        f"got {matches!r}"
    )
    return matches[0]["ActionsEnabled"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
