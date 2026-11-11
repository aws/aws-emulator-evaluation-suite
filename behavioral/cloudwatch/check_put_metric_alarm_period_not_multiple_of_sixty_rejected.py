"""put-metric-alarm-period-not-multiple-of-sixty-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-metric-alarm-period-not-multiple-of-sixty-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A standard-resolution PutMetricAlarm with a Period that is not a multiple of 60
    seconds (e.g. 45) is rejected and no alarm is persisted; a Period of 60 for the
    same alarm configuration succeeds."""
    cw = ctx.client("cloudwatch")
    ns = ctx.unique_name("sim2real-cw-period-")
    bad_name = ctx.unique_name("sim2real-cw-badperiod-")
    good_name = ctx.unique_name("sim2real-cw-goodperiod-")
    common = dict(
        Namespace=ns,
        MetricName="PeriodTestMetric",
        Statistic="Average",
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )

    error = _error(lambda: cw.put_metric_alarm(AlarmName=bad_name, Period=45, **common))
    assert error["Code"] == "ValidationError", f"expected ValidationError for Period=45, got {error!r}"
    assert error["Message"] == "Period must be 10, 20, 30 or a multiple of 60", error["Message"]

    existing = cw.describe_alarms(AlarmNames=[bad_name])["MetricAlarms"]
    assert existing == [], "an alarm with an invalid period should not have been persisted"

    cw.put_metric_alarm(AlarmName=good_name, Period=60, **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[good_name]))
    existing_good = cw.describe_alarms(AlarmNames=[good_name])["MetricAlarms"]
    assert len(existing_good) == 1, "positive control alarm with a valid period (60) was not created"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected real AWS to reject this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
