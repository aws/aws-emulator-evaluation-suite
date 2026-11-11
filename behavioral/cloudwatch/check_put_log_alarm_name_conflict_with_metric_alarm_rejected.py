"""put-log-alarm-name-conflict-with-metric-alarm-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-log-alarm-name-conflict-with-metric-alarm-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm on a name already used by a MetricAlarm fails with ValidationError and leaves the
    metric alarm untouched; once that alarm is deleted, the identical PutLogAlarm succeeds."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    alarm_name = ctx.unique_name("sim2real-namecollide-")
    namespace = ctx.unique_name("Sim2RealBehav")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="RequestLatency",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=50.0,
        ComparisonOperator="GreaterThanThreshold",
        ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    log_group_name = ctx.unique_name("/sim2real/behav-conflict/")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns ARNs with a trailing ":*" wildcard suffix; PutLogAlarm's
    # ScheduledQueryConfiguration.LogGroupIdentifiers rejects that suffix with a ValidationError.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    role_name = ctx.unique_name("sim2real-logalarm-conflict-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role(RoleName=role_name)))
    permissions_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults", "logs:DescribeLogGroups"],
                "Resource": log_group_arn,
            }
        ],
    }
    policy_name = "sim2real-scheduled-query-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions_policy))
    ctx.on_cleanup(lambda: _best_effort(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    put_log_alarm_kwargs = dict(
        AlarmName=alarm_name,
        ScheduledQueryConfiguration={
            "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
            "LogGroupIdentifiers": [log_group_arn],
            "ScheduledQueryRoleARN": role_arn,
            "AggregationExpression": "count(*)",
            "ScheduleConfiguration": {"ScheduleExpression": "rate(10 minutes)", "StartTimeOffset": 600},
        },
        QueryResultsToEvaluate=5,
        QueryResultsToAlarm=3,
        Threshold=10.0,
        ComparisonOperator="GreaterThanThreshold",
    )

    error = _client_error(lambda: cw.put_log_alarm(**put_log_alarm_kwargs))
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == f"AlarmName [{alarm_name}] is already used by another alarm of a different type", (
        f"unexpected message for the alarm-name conflict: {error.get('Message')!r}"
    )

    metric_described = cw.describe_alarms(AlarmNames=[alarm_name])
    assert len(metric_described["MetricAlarms"]) == 1, "original metric alarm no longer present after rejected PutLogAlarm"
    surviving = metric_described["MetricAlarms"][0]
    assert surviving["Namespace"] == namespace
    assert surviving["MetricName"] == "RequestLatency"
    assert surviving["Threshold"] == 50.0

    log_described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    assert log_described["LogAlarms"] == [], "a log alarm was unexpectedly created despite the name conflict"

    # Positive control: the identical call succeeds once the name is free.
    cw.delete_alarms(AlarmNames=[alarm_name])
    gone = cw.describe_alarms(AlarmNames=[alarm_name])
    assert gone["MetricAlarms"] == [], "the metric alarm must be gone before the name is reusable"

    cw.put_log_alarm(**put_log_alarm_kwargs)
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    restored = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    assert len(restored["LogAlarms"]) == 1, (
        "the identical PutLogAlarm call must succeed once the name is free, proving the earlier "
        f"rejection was the name collision and not a blanket refusal; got {restored['LogAlarms']!r}"
    )
    created = restored["LogAlarms"][0]
    assert created["Threshold"] == 10.0
    assert created["ComparisonOperator"] == "GreaterThanThreshold"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFound",
            "ResourceNotFoundException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
