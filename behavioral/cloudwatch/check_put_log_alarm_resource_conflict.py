"""put-log-alarm-resource-conflict."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-alarm-resource-conflict"
GROUP = "error-semantics"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm reusing an existing metric alarm's name fails ValidationError, changing nothing.

    Alarm names share one namespace across alarm types; once the metric alarm is deleted, the same
    PutLogAlarm call succeeds.
    """
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    log_group_name = ctx.unique_name("/sim2real/put-log-alarm-conflict-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    role_name = ctx.unique_name("sim2real-put-log-alarm-conflict-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "sim2real-scheduled-query-exec"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "logs:StartQuery",
                            "logs:StopQuery",
                            "logs:GetQueryResults",
                            "logs:DescribeLogGroups",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    def _role_ready() -> bool:
        try:
            iam.get_role(RoleName=role_name)
            iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            return True
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    deadline = time.monotonic() + 30.0
    while not _role_ready():
        if time.monotonic() > deadline:
            raise AssertionError("scheduled-query role/policy not visible within 30s of creation")
        time.sleep(1.0)

    def _log_alarm_config():
        return {
            "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
            "LogGroupIdentifiers": [log_group_arn],
            "ScheduledQueryRoleARN": role_arn,
            "AggregationExpression": "count(*)",
            "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 300},
        }

    # Positive control: the same real role and log group under a fresh AlarmName succeeds. A fake
    # role ARN alone triggers the same ValidationError, so the rejection below is the name conflict.
    control_name = ctx.unique_name("sim2real-put-log-alarm-control-")
    cw.put_log_alarm(
        AlarmName=control_name,
        ScheduledQueryConfiguration=_log_alarm_config(),
        QueryResultsToEvaluate=5,
        QueryResultsToAlarm=3,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_name]))
    control_described = cw.describe_alarms(AlarmNames=[control_name], AlarmTypes=["LogAlarm"])
    assert len(control_described["LogAlarms"]) == 1, "positive control PutLogAlarm did not create a LogAlarm"

    # Break exactly one thing: claim the AlarmName with an ordinary metric alarm first,
    # then send the identical, otherwise-valid PutLogAlarm request against that name.
    alarm_name = ctx.unique_name("sim2real-alarm-name-conflict-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Statistic="Average",
        Period=300,
        EvaluationPeriods=1,
        Threshold=99.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    before = cw.describe_alarms(AlarmNames=[alarm_name])
    assert len(before["MetricAlarms"]) == 1
    assert before["LogAlarms"] == []

    try:
        cw.put_log_alarm(
            AlarmName=alarm_name,
            ScheduledQueryConfiguration=_log_alarm_config(),
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
        )
        raise AssertionError("expected ValidationError when reusing an existing metric alarm's name")
    except ClientError as e:
        error = e.response["Error"]
        assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
        assert error.get("Message") == f"AlarmName [{alarm_name}] is already used by another alarm of a different type", (
            f"unexpected message for the alarm-name conflict: {error.get('Message')!r}"
        )

    # The forbidden effect did not happen: the alarm is still the original metric alarm.
    after = cw.describe_alarms(AlarmNames=[alarm_name])
    assert len(after["MetricAlarms"]) == 1
    assert after["LogAlarms"] == []
    assert after["MetricAlarms"][0]["MetricName"] == "CPUUtilization"

    # Restore: once the conflicting metric alarm is gone, the identical PutLogAlarm call
    # succeeds -- this is a name-namespace conflict, not a permanent rejection of the shape.
    cw.delete_alarms(AlarmNames=[alarm_name])

    restore_deadline = time.monotonic() + 30.0
    while True:
        try:
            cw.put_log_alarm(
                AlarmName=alarm_name,
                ScheduledQueryConfiguration=_log_alarm_config(),
                QueryResultsToEvaluate=5,
                QueryResultsToAlarm=3,
                Threshold=10.0,
                ComparisonOperator="GreaterThanThreshold",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ValidationError" or time.monotonic() > restore_deadline:
                raise
            time.sleep(2.0)

    restored = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    assert len(restored["LogAlarms"]) == 1, "PutLogAlarm did not succeed once the conflicting name was freed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
