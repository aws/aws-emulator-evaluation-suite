"""put-log-alarm-name-conflict-with-existing-metric-alarm."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-alarm-name-conflict-with-existing-metric-alarm"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm reusing an alarm name already owned by a metric alarm raises ValidationError."""
    cw = ctx.client("cloudwatch")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    alarm_name = ctx.unique_name("sim2real-logalarm-conflict-")

    # 1. Claim the alarm name with an ordinary metric alarm.
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=80.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # 2. Build a plausible ScheduledQueryConfiguration (real IAM role + real log group)
    # so any conflict we hit is the alarm-name conflict, not a missing-resource error.
    role_name = ctx.unique_name("sim2real-logalarm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudwatch.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="logs-query-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:StartQuery",
                            "logs:GetQueryResults",
                            "logs:StopQuery",
                            "logs:DescribeLogGroups",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logs-query-access")
    )

    log_group_name = ctx.unique_name("/sim2real/logalarm-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # Wait for the role + inline policy to actually be visible (IAM is eventually
    # consistent) before CloudWatch touches the role, instead of a fixed sleep.
    def _role_ready() -> bool:
        try:
            iam.get_role(RoleName=role_name)
            iam.get_role_policy(RoleName=role_name, PolicyName="logs-query-access")
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    _poll_until(_role_ready, timeout_s=30.0, interval_s=1.0)

    error = _client_error(
        lambda: cw.put_log_alarm(
            AlarmName=alarm_name,
            ScheduledQueryConfiguration={
                "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
                "LogGroupIdentifiers": [log_group_name],
                "ScheduledQueryRoleARN": role_arn,
                "AggregationExpression": "count(*)",
                "ScheduleConfiguration": {
                    "ScheduleExpression": "rate(5 minutes)",
                    "StartTimeOffset": 360,
                },
            },
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == f"AlarmName [{alarm_name}] is already used by another alarm of a different type", (
        f"unexpected message for the alarm-name conflict: {error.get('Message')!r}"
    )

    # The rejection must be real, not cosmetic: an independent read at the destination proves
    # the pre-existing metric alarm survived untouched and no log alarm was created in its place.
    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "LogAlarm"])
    metric_alarms = described.get("MetricAlarms", [])
    assert len(metric_alarms) == 1, (
        f"expected the original metric alarm to survive the rejected PutLogAlarm, got {metric_alarms}"
    )
    survivor = metric_alarms[0]
    assert survivor["Namespace"] == "AWS/EC2", survivor
    assert survivor["MetricName"] == "CPUUtilization", survivor
    assert survivor["Threshold"] == 80.0, survivor
    assert described.get("LogAlarms", []) == [], (
        f"a log alarm must not have been created under the conflicting name, got {described['LogAlarms']}"
    )


def _poll_until(probe, *, timeout_s: float = 30.0, interval_s: float = 1.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
