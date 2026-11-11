"""describe-alarm-contributors-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-alarm-contributors-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeAlarmContributors fails with ResourceNotFoundException "No alarm for name <name> was
    found" for a name never created, and with ValidationError "Alarm <name> is not a multi time
    series alarm" for an existing ordinary metric alarm."""
    cw = ctx.client("cloudwatch")

    never_created = ctx.unique_name("sim2real-never-created-alarm-")
    try:
        cw.describe_alarm_contributors(AlarmName=never_created)
        raise AssertionError("expected ResourceNotFoundException for a never-created alarm name")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        expected_message = f"No alarm for name {never_created} was found"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    ordinary_alarm = ctx.unique_name("sim2real-ordinary-metric-alarm-")
    cw.put_metric_alarm(
        AlarmName=ordinary_alarm,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ordinary_alarm]))

    # The alarm genuinely exists (positive control)...
    described = cw.describe_alarms(AlarmNames=[ordinary_alarm])
    assert len(described["MetricAlarms"]) == 1

    # ...but it is not a contributor-based alarm: a ValidationError rather than a 404
    # ResourceNotFoundException, as the alarm itself exists but is the wrong type.
    try:
        cw.describe_alarm_contributors(AlarmName=ordinary_alarm)
        raise AssertionError("expected ValidationError for a non-contributor-based alarm")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = e.response["Error"].get("Message")
        assert code == "ValidationError", f"expected ValidationError, got {code}"
        expected_message = f"Alarm {ordinary_alarm} is not a multi time series alarm"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
