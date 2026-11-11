"""new-alarm-starts-insufficient-data."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "new-alarm-starts-insufficient-data"
GROUP = "state-transitions"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created metric alarm on an un-evaluated metric begins in state INSUFFICIENT_DATA."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-cw-fresh-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="NeverEvaluated",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"])
    alarms = described["MetricAlarms"]
    assert len(alarms) == 1, alarms
    assert alarms[0]["StateValue"] == "INSUFFICIENT_DATA", alarms[0]["StateValue"]
    assert alarms[0]["ActionsEnabled"] is True, (
        f"expected a freshly created alarm to default ActionsEnabled=True, got {alarms[0]['ActionsEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
