"""enable-alarm-actions-sets-flag."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "enable-alarm-actions-sets-flag"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableAlarmActions flips ActionsEnabled to true for the named alarm, and
    silently no-ops for a nonexistent alarm name in the same batch (no error)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-ns-")
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    bogus_name = ctx.unique_name("sim2real-behav-alarm-missing-")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="ActionsMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    before = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert before["ActionsEnabled"] is False, (
        f"newly created alarm must start with ActionsEnabled=False, got {before['ActionsEnabled']!r}"
    )

    # Distinct contract boundary: this operation never raises, even when the
    # batch also names an alarm that doesn't exist -- it is silently ignored.
    resp = cw.enable_alarm_actions(AlarmNames=[alarm_name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"EnableAlarmActions must not raise for a batch containing an unknown "
        f"alarm name, got HTTPStatusCode={resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    described_bogus = cw.describe_alarms(AlarmNames=[bogus_name])
    assert described_bogus["MetricAlarms"] == [] and described_bogus["CompositeAlarms"] == [], (
        f"EnableAlarmActions must not materialize an alarm for the unknown name "
        f"{bogus_name!r}, got {described_bogus['MetricAlarms'] + described_bogus['CompositeAlarms']!r}"
    )

    after = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert after["ActionsEnabled"] is True, (
        f"ActionsEnabled must flip to true after EnableAlarmActions, got {after['ActionsEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
