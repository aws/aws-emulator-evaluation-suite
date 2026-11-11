"""put-metric-alarm-rejects-statistic-and-extended-statistic."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-alarm-rejects-statistic-and-extended-statistic"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict of the ClientError it must raise.

    An unexpected SUCCESS raises rather than returning a falsy sentinel.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects Statistic+ExtendedStatistic, but the call succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm rejects supplying both Statistic and ExtendedStatistic; the
    same alarm configuration with only Statistic set succeeds, proving the
    rejection isn't a blanket failure of this call shape."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    good_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-good-")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")

    def op():
        return cw.put_metric_alarm(
            AlarmName=alarm_name,
            Namespace=namespace,
            MetricName="Conflicting",
            Statistic="Average",
            ExtendedStatistic="p95",
            Period=60,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
        )

    error = _err(op)
    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError for Statistic+ExtendedStatistic, got {error!r}"
    )
    assert error.get("Message") == (
        "PutMetricAlarm request can not be made with both Statistic and ExtendedStatistic "
        "parameters. Only one of them should be present"
    ), error.get("Message")

    # The rejected call must not have created the alarm.
    resp = cw.describe_alarms(AlarmNames=[alarm_name])
    assert resp.get("MetricAlarms", []) == [], "rejected PutMetricAlarm must not create the alarm"

    # Positive control: the identical configuration with only Statistic set
    # (no ExtendedStatistic) succeeds, proving the rejection above targets the
    # conflicting combination and not the call shape in general.
    cw.put_metric_alarm(
        AlarmName=good_name,
        Namespace=namespace,
        MetricName="Conflicting",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[good_name]))
    good_resp = cw.describe_alarms(AlarmNames=[good_name])
    assert len(good_resp.get("MetricAlarms", [])) == 1, (
        "positive control alarm with only Statistic set was not created"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
