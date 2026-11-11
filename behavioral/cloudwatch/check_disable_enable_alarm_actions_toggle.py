"""disable-enable-alarm-actions-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "disable-enable-alarm-actions-toggle"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAlarmActions / EnableAlarmActions flip an existing alarm's ActionsEnabled flag
    as observed via DescribeAlarms, independent of the alarm's evaluation state."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        MetricName="Sim2RealMetric",
        Namespace="Sim2RealBehavioral",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
        Tags=[{"Key": "sim2real-check", "Value": "disable-enable-alarm-actions-toggle"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    def describe():
        return cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]

    alarm = describe()
    assert alarm["ActionsEnabled"] is True, f"new alarm should default ActionsEnabled=True, got {alarm['ActionsEnabled']!r}"

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real forced state for toggle independence")
    state_forced = describe()["StateValue"]
    assert state_forced == "ALARM", f"expected forced StateValue=ALARM, got {state_forced!r}"

    cw.disable_alarm_actions(AlarmNames=[name])
    alarm = describe()
    assert alarm["ActionsEnabled"] is False, f"ActionsEnabled should be False after DisableAlarmActions, got {alarm['ActionsEnabled']!r}"
    assert alarm["StateValue"] == "ALARM", f"DisableAlarmActions must not change StateValue, got {alarm['StateValue']!r}"

    cw.enable_alarm_actions(AlarmNames=[name])
    alarm = describe()
    assert alarm["ActionsEnabled"] is True, f"ActionsEnabled should be True after EnableAlarmActions, got {alarm['ActionsEnabled']!r}"
    assert alarm["StateValue"] == "ALARM", f"EnableAlarmActions must not change StateValue, got {alarm['StateValue']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
