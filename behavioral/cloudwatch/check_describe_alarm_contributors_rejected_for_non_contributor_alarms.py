"""describe-alarm-contributors-rejected-for-non-contributor-alarms."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-rejected-for-non-contributor-alarms"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors on a GROUP BY Metrics Insights alarm succeeds, while on a plain
    metric alarm and on a composite over it it fails with ValidationError "Alarm <name> is not a
    multi time series alarm"; it does not return an empty contributor list."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "describe_alarm_contributors"):
        raise AssertionError("unreachable: boto3 cloudwatch client has no DescribeAlarmContributors support")

    # Positive control: a multi-time-series (GROUP BY Metrics Insights) alarm IS
    # contributor-based, so DescribeAlarmContributors against it must not raise ValidationError.
    namespace = ctx.unique_name("Sim2RealDACContrib")
    metric_name = "Latency"
    dim_key = "Contributor"
    mts_alarm_name = ctx.unique_name("sim2real-behav-dac-mts-")
    query = (
        f'SELECT AVG({metric_name}) FROM SCHEMA("{namespace}", {dim_key}) GROUP BY {dim_key} '
        "ORDER BY AVG() DESC LIMIT 10"
    )
    cw.put_metric_alarm(
        AlarmName=mts_alarm_name,
        Metrics=[{"Id": "m1", "Expression": query, "Period": 60, "ReturnData": True}],
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="notBreaching",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[mts_alarm_name]))
    try:
        cw.describe_alarm_contributors(AlarmName=mts_alarm_name)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            "positive control: a genuinely multi-time-series (GROUP BY) alarm must not be "
            f"rejected as non-contributor-based, got {code}"
        ) from exc

    metric_alarm_name = ctx.unique_name("sim2real-behav-dac-metric-")
    cw.put_metric_alarm(
        AlarmName=metric_alarm_name,
        Namespace="Sim2RealBehavioral",
        MetricName="ProbeMetric",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[metric_alarm_name]))

    composite_alarm_name = ctx.unique_name("sim2real-behav-dac-composite-")
    cw.put_composite_alarm(AlarmName=composite_alarm_name, AlarmRule=f'ALARM("{metric_alarm_name}")')
    # Registered after the metric alarm's cleanup -> runs first (LIFO), so the metric alarm is
    # not deleted while the composite still references it.
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[composite_alarm_name]))

    code, message = _client_error(lambda: cw.describe_alarm_contributors(AlarmName=metric_alarm_name))
    assert code == "ValidationError", f"metric alarm: expected ValidationError, got {code}"
    expected_message = f"Alarm {metric_alarm_name} is not a multi time series alarm"
    assert message == expected_message, f"metric alarm: expected message {expected_message!r}, got {message!r}"

    code, message = _client_error(lambda: cw.describe_alarm_contributors(AlarmName=composite_alarm_name))
    assert code == "ValidationError", f"composite alarm: expected ValidationError, got {code}"
    expected_message = f"Alarm {composite_alarm_name} is not a multi time series alarm"
    assert message == expected_message, f"composite alarm: expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an emulator
    accepting a call AWS refuses is never reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ValidationError rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
