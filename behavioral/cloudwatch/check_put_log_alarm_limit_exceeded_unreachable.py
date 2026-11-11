"""put-log-alarm-limit-exceeded-unreachable."""
from __future__ import annotations

import json

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-log-alarm-limit-exceeded-unreachable"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

# "Maximum Log Alarms per account" -- fixed, non-adjustable quota (limited by the
# CloudWatch Logs AWS-managed Scheduled Query quota).
_QUOTA = 1000


@tags("axis:happy-path", "cap:c1", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm accepts a create while the account is under its ~1,000 log-alarm quota, and the
    account-wide LogAlarm count moves by exactly 1 on create and back to baseline on delete.
    Exhausting the quota is impractical: PutLogAlarm is throttled to 3 requests/second.
    """
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    if not hasattr(cw, "put_log_alarm"):
        raise AssertionError("cloudwatch client lacks put_log_alarm; botocore predates the LogAlarm API")

    baseline = _count_existing_log_alarms(cw)

    # A real, live-state assertion on the boundary this check targets: the account must
    # not already be sitting at/over the documented, non-adjustable quota. If it were,
    # PutLogAlarm would already be rejecting every new log alarm with LimitExceededFault
    # for reasons unrelated to what this check is verifying.
    assert baseline < _QUOTA, (
        f"account already has {baseline} log alarms, at/above the documented, "
        f"non-adjustable quota of ~{_QUOTA}; PutLogAlarm should already be rejecting new "
        "log alarms with LimitExceededFault for this account, which this check doesn't "
        "independently re-verify"
    )

    log_group_name = ctx.unique_name("/sim2real/behav/logalarm-limit-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _best_effort(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns ARNs with a trailing ":*" wildcard suffix; PutLogAlarm's
    # ScheduledQueryConfiguration.LogGroupIdentifiers rejects that suffix with a ValidationError.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    role_name = ctx.unique_name("sim2real-logalarm-limit-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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

    alarm_name = ctx.unique_name("sim2real-logalarm-limit-")
    cw.put_log_alarm(
        AlarmName=alarm_name,
        AlarmDescription="behavioral check: quota headroom positive control",
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
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    # Independent read (DescribeAlarms, not PutLogAlarm's own response) on the exact
    # side-channel this check's quota boundary reads: creating one alarm while
    # comfortably under quota must move the account-wide count by exactly 1, not leave
    # it unchanged (a target that silently no-ops the create) and not jump by more than
    # 1 (a target that fans out hidden alarms).
    after_create = _count_existing_log_alarms(cw)
    assert after_create == baseline + 1, (
        "expected the account-wide LogAlarm count to move by exactly 1 after a single "
        f"PutLogAlarm while under quota, went {baseline} -> {after_create}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])
    after_delete = _count_existing_log_alarms(cw)
    assert after_delete == baseline, (
        "expected the account-wide LogAlarm count to return to its pre-check baseline "
        f"of {baseline} after DeleteAlarms, got {after_delete}"
    )


def _count_existing_log_alarms(cw) -> int:
    total = 0
    token = None
    while True:
        kwargs = {"AlarmTypes": ["LogAlarm"], "MaxRecords": 100}
        if token:
            kwargs["NextToken"] = token
        page = cw.describe_alarms(**kwargs)
        total += len(page.get("LogAlarms", []))
        token = page.get("NextToken")
        if not token:
            break
    return total


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
