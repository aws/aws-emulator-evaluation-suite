"""new-metric-alarm-starts-insufficient-data."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "new-metric-alarm-starts-insufficient-data"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A freshly created metric alarm with no published data begins in INSUFFICIENT_DATA."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-newalarm-")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    resp = cw.describe_alarms(AlarmNames=[alarm_name])
    alarms = resp["MetricAlarms"]
    assert len(alarms) == 1, f"expected exactly one alarm, got {alarms}"
    assert alarms[0]["StateValue"] == "INSUFFICIENT_DATA", (
        f"expected initial state INSUFFICIENT_DATA, got {alarms[0]['StateValue']}"
    )
    assert alarms[0]["ActionsEnabled"] is True, (
        f"expected ActionsEnabled True by default, got {alarms[0]['ActionsEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
