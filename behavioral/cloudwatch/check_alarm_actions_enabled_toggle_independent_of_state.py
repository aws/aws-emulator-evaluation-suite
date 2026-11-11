"""alarm-actions-enabled-toggle-independent-of-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "alarm-actions-enabled-toggle-independent-of-state"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAlarmActions/EnableAlarmActions toggle ActionsEnabled without altering StateValue,
    and the forced StateValue set via SetAlarmState is visible immediately after the call."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-actionstoggle-")
    namespace = ctx.unique_name("Sim2RealBehav/")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=True,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    baseline = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert baseline["ActionsEnabled"] is True, baseline["ActionsEnabled"]

    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason="force-for-toggle-test")
    just_forced = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert just_forced["StateValue"] == "ALARM", just_forced["StateValue"]

    cw.disable_alarm_actions(AlarmNames=[alarm_name])
    disabled = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert disabled["ActionsEnabled"] is False, disabled["ActionsEnabled"]
    assert disabled["StateValue"] == "ALARM", disabled["StateValue"]

    cw.enable_alarm_actions(AlarmNames=[alarm_name])
    enabled = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert enabled["ActionsEnabled"] is True, enabled["ActionsEnabled"]
    assert enabled["StateValue"] == "ALARM", enabled["StateValue"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
