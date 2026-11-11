"""op-contract-enableAlarmActions-dup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-enableAlarmActions-dup"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableAlarmActions flips ActionsEnabled to true for the named alarm, and
    silently no-ops for a nonexistent alarm name in the same batch (no error)."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cw-ns-")
    alarm_name = ctx.unique_name("sim2real-behav-cw-alarm-")
    bogus_name = ctx.unique_name("sim2real-behav-cw-alarm-missing-")

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
        Tags=[{"Key": "sim2real-owner", "Value": "cw-enable-alarm-actions-contract"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    before = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert before["ActionsEnabled"] is False, (
        f"expected ActionsEnabled=False right after creation, got {before['ActionsEnabled']}"
    )

    # distinct contract boundary: this operation never raises, even when the batch
    # also names an alarm that doesn't exist -- it is silently ignored rather than
    # rejected or fabricated into a new alarm.
    resp = cw.enable_alarm_actions(AlarmNames=[alarm_name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected the batch call to succeed despite the unknown name, got "
        f"{resp['ResponseMetadata']['HTTPStatusCode']}"
    )

    # independent read: the unknown name must not have been silently materialized
    # into a real alarm as a side effect of being named in the batch.
    described_bogus = cw.describe_alarms(AlarmNames=[bogus_name])
    assert described_bogus["MetricAlarms"] == [] and described_bogus["CompositeAlarms"] == [], (
        "EnableAlarmActions must not create an alarm for an unknown name in its batch, got "
        f"{described_bogus['MetricAlarms']!r} / {described_bogus['CompositeAlarms']!r}"
    )

    after = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert after["ActionsEnabled"] is True, (
        f"ActionsEnabled must flip to true for the real alarm, got {after['ActionsEnabled']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
