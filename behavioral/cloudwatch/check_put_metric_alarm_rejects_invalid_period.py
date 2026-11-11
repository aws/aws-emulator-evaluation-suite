"""put-metric-alarm-rejects-invalid-period."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-alarm-rejects-invalid-period"
GROUP = 'overly-permissive'
SERVICES = ['cloudwatch']

def _err(fn):
    """Call fn(); return the botocore Error dict of the ClientError it must raise.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: an emulator that accepts
    input real AWS rejects is the strongest signal available.
    """
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects Period=45, but the call succeeded: {result!r}")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutMetricAlarm rejects a Period that is not a valid CloudWatch resolution (45), and the
    identical alarm configuration with a valid Period (60) succeeds -- the positive control that
    tells "rejects Period=45" apart from "rejects every PutMetricAlarm"."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    bad_name = ctx.unique_name("sim2real-behav-cwprobe-badperiod-")
    good_name = ctx.unique_name("sim2real-behav-cwprobe-goodperiod-")
    common = dict(
        Namespace=namespace,
        MetricName="BadPeriod",
        Statistic="Average",
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )

    error = _err(lambda: cw.put_metric_alarm(AlarmName=bad_name, Period=45, **common))
    assert error.get("Code") == "ValidationError", f"expected ValidationError for Period=45, got {error!r}"
    assert error.get("Message") == "Period must be 10, 20, 30 or a multiple of 60", error.get("Message")

    resp = cw.describe_alarms(AlarmNames=[bad_name])
    assert resp.get("MetricAlarms", []) == [], "rejected PutMetricAlarm must not create the alarm"

    cw.put_metric_alarm(AlarmName=good_name, Period=60, **common)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[good_name]))
    created = cw.describe_alarms(AlarmNames=[good_name]).get("MetricAlarms", [])
    assert len(created) == 1, (
        f"positive control: the identical alarm with a valid Period=60 must be created, got {created!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
