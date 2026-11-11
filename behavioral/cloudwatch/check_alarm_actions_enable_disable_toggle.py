"""alarm-actions-enable-disable-toggle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarm-actions-enable-disable-toggle"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableAlarmActions/DisableAlarmActions toggle the ActionsEnabled attribute on
    an alarm, and the toggle does not affect the alarm's StateValue."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealBehavioral-")

    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName="InvocationCount",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is True, "new alarm should default ActionsEnabled=True"
    state_before = alarm["StateValue"]

    cw.disable_alarm_actions(AlarmNames=[name])
    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is False, f"expected ActionsEnabled=False after DisableAlarmActions, got {alarm['ActionsEnabled']}"
    assert alarm["StateValue"] == state_before, "disabling actions must not change StateValue"

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="sim2real actions disabled still transitions")
    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["StateValue"] == "ALARM", "state must still transition while actions are disabled"
    assert alarm["ActionsEnabled"] is False, f"ActionsEnabled must remain False across the SetAlarmState call, got {alarm['ActionsEnabled']}"

    cw.enable_alarm_actions(AlarmNames=[name])
    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is True, f"expected ActionsEnabled=True after EnableAlarmActions, got {alarm['ActionsEnabled']}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
