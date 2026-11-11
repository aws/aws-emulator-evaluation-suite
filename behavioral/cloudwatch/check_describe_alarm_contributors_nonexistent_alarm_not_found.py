"""describe-alarm-contributors-nonexistent-alarm-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-nonexistent-alarm-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors on an ordinary single-metric alarm fails with ValidationError
    "Alarm <name> is not a multi time series alarm"; it does not return an empty list."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-alarm-contributors-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # Positive control: the alarm genuinely exists as an ordinary metric alarm, so the
    # rejection below is attributable to its type, not to a broken/nonexistent target.
    described = cw.describe_alarms(AlarmNames=[alarm_name])
    assert len(described["MetricAlarms"]) == 1, "sanity: the alarm must exist before probing DescribeAlarmContributors"

    code, message = _client_error(lambda: cw.describe_alarm_contributors(AlarmName=alarm_name))
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = f"Alarm {alarm_name} is not a multi time series alarm"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
