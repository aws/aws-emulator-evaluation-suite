"""disable-alarm-actions-clears-flag."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "disable-alarm-actions-clears-flag"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableAlarmActions flips ActionsEnabled to false for the named alarm, and
    silently no-ops for a nonexistent alarm name in the same batch: no error, and
    no alarm is ever created for the missing name."""
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
        ActionsEnabled=True,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    before = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert before["ActionsEnabled"] is True, "fresh alarm must start with ActionsEnabled=True"

    # Distinct contract boundary: this operation never raises, even when the
    # batch also names an alarm that doesn't exist -- it is silently ignored.
    resp = cw.disable_alarm_actions(AlarmNames=[alarm_name, bogus_name])
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"disabling a batch naming a missing alarm must not raise, got "
        f"{resp['ResponseMetadata']}"
    )

    after = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert after["ActionsEnabled"] is False, "ActionsEnabled must flip to false"

    # "Silently no-ops" means more than "did not raise": the missing name must
    # never have caused an alarm to spring into existence under that name either.
    missing = cw.describe_alarms(AlarmNames=[bogus_name])
    assert missing["MetricAlarms"] == [] and missing["CompositeAlarms"] == [], (
        f"DisableAlarmActions must not create an alarm for a missing name, got "
        f"{missing}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
