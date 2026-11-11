"""delete-alarms-ignores-missing-names."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-alarms-ignores-missing-names"
GROUP = "state"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlarms with a batch containing both an existing alarm name and a
    nonexistent one succeeds as a whole (silently ignores the missing name) and still
    removes the existing alarm."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cw-delbatch-")
    missing_name = ctx.unique_name("sim2real-behav-cw-neverexisted-")
    namespace = "Sim2Real/BehavioralCheck"
    metric_name = ctx.unique_name("DelBatchMetric-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=100.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    exists = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(exists) == 1, f"expected the positive control alarm to exist before delete, got {exists}"

    # No exception expected, even though missing_name does not exist.
    cw.delete_alarms(AlarmNames=[alarm_name, missing_name])

    gone = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert gone == [], "alarm was not removed by the batched DeleteAlarms call"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
