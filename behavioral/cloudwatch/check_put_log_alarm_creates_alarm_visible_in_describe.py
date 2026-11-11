"""put-log-alarm-creates-alarm-visible-in-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-log-alarm-creates-alarm-visible-in-describe"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm creates a LogAlarm surfaced by DescribeAlarms; DeleteAlarms removes it."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    tag_set = [{"Key": "sim2real-check", "Value": CHECK}]

    log_group_name = ctx.unique_name("/sim2real/behav/")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns ARNs with a trailing ":*" wildcard suffix; PutLogAlarm's
    # ScheduledQueryConfiguration.LogGroupIdentifiers rejects that suffix with a ValidationError.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    role_name = ctx.unique_name("sim2real-logalarm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy), Tags=tag_set
    )["Role"]["Arn"]
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

    alarm_name = ctx.unique_name("sim2real-logalarm-")
    scheduled_query_configuration = {
        "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
        "LogGroupIdentifiers": [log_group_arn],
        "ScheduledQueryRoleARN": role_arn,
        "AggregationExpression": "count(*)",
        "ScheduleConfiguration": {"ScheduleExpression": "rate(10 minutes)", "StartTimeOffset": 600},
    }

    def _put():
        return cw.put_log_alarm(
            AlarmName=alarm_name,
            AlarmDescription="behavioral check log alarm",
            ScheduledQueryConfiguration=scheduled_query_configuration,
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
            Tags=tag_set,
        )

    # The scheduled query role's trust and inline permissions policy are eventually
    # consistent; PutLogAlarm validates the role at creation time and can reject a
    # just-created role with a permanent-looking error until IAM propagation catches up.
    put_resp = _retry_on_error(_put, timeout_s=60, interval_s=5)
    # PutLogAlarm's response does not include the alarm's ARN (unlike PutMetricAlarm's synchronous
    # counterparts); the ARN is only surfaced later via DescribeAlarms, so assert against that instead.
    assert isinstance(put_resp, dict)
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    log_alarms = described["LogAlarms"]
    assert len(log_alarms) == 1, f"expected exactly 1 log alarm named {alarm_name}, got {len(log_alarms)}"
    alarm = log_alarms[0]
    assert alarm["AlarmName"] == alarm_name
    assert alarm["AlarmArn"].startswith("arn:aws:cloudwatch:") and alarm_name in alarm["AlarmArn"]
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold"
    assert alarm["Threshold"] == 10.0
    assert alarm["QueryResultsToEvaluate"] == 5
    assert alarm["QueryResultsToAlarm"] == 3
    assert alarm["ScheduledQueryConfiguration"]["ScheduledQueryRoleARN"] == role_arn, (
        f"expected round-tripped role ARN {role_arn}, "
        f"got {alarm['ScheduledQueryConfiguration']['ScheduledQueryRoleARN']}"
    )
    assert alarm["ScheduledQueryConfiguration"]["LogGroupIdentifiers"] == [log_group_arn], (
        f"expected round-tripped log group identifiers [{log_group_arn}], "
        f"got {alarm['ScheduledQueryConfiguration']['LogGroupIdentifiers']}"
    )
    assert described.get("MetricAlarms", []) == []
    assert described.get("CompositeAlarms", []) == []

    cw.delete_alarms(AlarmNames=[alarm_name])

    described_after = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    assert described_after["LogAlarms"] == [], f"log alarm {alarm_name} still present after DeleteAlarms"


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


def _retry_on_error(fn, *, timeout_s: float = 60.0, interval_s: float = 5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc if last_exc is not None else AssertionError("retry loop exited without success or exception")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
