"""describe-alarm-contributors-nonexistent-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-nonexistent-resource"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors fails with ResourceNotFoundException "No alarm for name <name> was
    found" for a name that never existed, and with ValidationError "Alarm <name> is not a multi time
    series alarm" for an existing single-metric alarm, which has no per-contributor breakdown."""
    cw = ctx.client("cloudwatch")

    never_created = ctx.unique_name("sim2real-behav-cw-missing-alarm-")
    code_missing, message_missing = _client_error(
        lambda: cw.describe_alarm_contributors(AlarmName=never_created)
    )
    assert code_missing == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_missing!r}"
    expected_message = f"No alarm for name {never_created} was found"
    assert message_missing == expected_message, f"expected message {expected_message!r}, got {message_missing!r}"

    plain_alarm_name = ctx.unique_name("sim2real-behav-cw-plain-alarm-")
    cw.put_metric_alarm(
        AlarmName=plain_alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=90.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[plain_alarm_name]))

    described = cw.describe_alarms(AlarmNames=[plain_alarm_name])
    assert len(described["MetricAlarms"]) == 1, (
        f"sanity: the plain metric alarm must exist, found {len(described['MetricAlarms'])}"
    )

    code_wrong_type, message_wrong_type = _client_error(
        lambda: cw.describe_alarm_contributors(AlarmName=plain_alarm_name)
    )
    assert code_wrong_type == "ValidationError", (
        f"expected ValidationError for a non-contributor-based alarm, got {code_wrong_type!r}"
    )
    expected_wrong_type = f"Alarm {plain_alarm_name} is not a multi time series alarm"
    assert message_wrong_type == expected_wrong_type, (
        f"expected message {expected_wrong_type!r}, got {message_wrong_type!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an emulator
    accepting a call AWS refuses is never reported as a mere error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
