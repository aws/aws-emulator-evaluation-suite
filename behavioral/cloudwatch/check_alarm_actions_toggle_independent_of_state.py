"""alarm-actions-toggle-independent-of-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarm-actions-toggle-independent-of-state"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAlarmActions/EnableAlarmActions flip ActionsEnabled without touching StateValue."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-cw-alarm-")
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=ctx.unique_name("sim2real-cw-ns-"),
        MetricName="DummyMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    baseline = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert baseline["ActionsEnabled"] is True, "PutMetricAlarm(ActionsEnabled=True) must be honored immediately"

    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="force-alarm")

    cw.disable_alarm_actions(AlarmNames=[name])
    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is False, "DisableAlarmActions must clear ActionsEnabled"
    assert alarm["StateValue"] == "ALARM", "disabling actions must not change StateValue"

    cw.enable_alarm_actions(AlarmNames=[name])
    alarm = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]
    assert alarm["ActionsEnabled"] is True, "EnableAlarmActions must restore ActionsEnabled"
    assert alarm["StateValue"] == "ALARM", "enabling actions must not change StateValue"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
