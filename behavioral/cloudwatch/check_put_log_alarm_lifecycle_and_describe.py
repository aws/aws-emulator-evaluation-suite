"""put-log-alarm-lifecycle-and-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-log-alarm-lifecycle-and-describe"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]

_QUERY_EXECUTION_POLICY = {
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm creates a log-based alarm that appears in DescribeAlarms and can be
    removed via DeleteAlarms, following the standard alarm lifecycle."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_log_alarm"):
        raise AssertionError("cloudwatch client lacks put_log_alarm; botocore predates the LogAlarm API")

    log_group_arn, log_group_name = _create_log_group(ctx)
    role_arn = _create_scheduled_query_role(ctx)

    alarm_name = ctx.unique_name("sim2real-log-alarm-")
    config = {
        "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
        "LogGroupIdentifiers": [log_group_arn],
        "ScheduledQueryRoleARN": role_arn,
        "AggregationExpression": "count(*)",
        "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
    }

    def _put():
        return cw.put_log_alarm(
            AlarmName=alarm_name,
            AlarmDescription="sim2real behavioral log alarm",
            ScheduledQueryConfiguration=config,
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
        )

    _retry_on_error(_put, attempts=8, delay_s=5.0)
    ctx.on_cleanup(lambda: _safe(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    log_alarms = described.get("LogAlarms", [])
    assert len(log_alarms) == 1, f"expected 1 log alarm in DescribeAlarms, got {log_alarms}"
    entry = log_alarms[0]
    assert entry["AlarmName"] == alarm_name, f"expected AlarmName {alarm_name!r}, got {entry.get('AlarmName')!r}"
    assert entry["AlarmArn"].startswith("arn:aws:cloudwatch:") and alarm_name in entry["AlarmArn"], (
        f"expected AlarmArn for {alarm_name!r} under arn:aws:cloudwatch:, got {entry.get('AlarmArn')!r}"
    )
    assert entry["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected ComparisonOperator 'GreaterThanThreshold', got {entry.get('ComparisonOperator')!r}"
    )
    assert entry["Threshold"] == 10.0, f"expected Threshold 10.0, got {entry.get('Threshold')!r}"
    assert entry["QueryResultsToEvaluate"] == 5, (
        f"expected QueryResultsToEvaluate 5, got {entry.get('QueryResultsToEvaluate')!r}"
    )
    assert entry["QueryResultsToAlarm"] == 3, (
        f"expected QueryResultsToAlarm 3, got {entry.get('QueryResultsToAlarm')!r}"
    )
    assert entry["ScheduledQueryConfiguration"]["ScheduledQueryRoleARN"] == role_arn, (
        f"expected ScheduledQueryRoleARN {role_arn!r}, got "
        f"{entry['ScheduledQueryConfiguration'].get('ScheduledQueryRoleARN')!r}"
    )
    assert described.get("MetricAlarms", []) == [], (
        f"log alarm unexpectedly also returned as a metric alarm: {described.get('MetricAlarms')!r}"
    )
    assert described.get("CompositeAlarms", []) == [], (
        f"log alarm unexpectedly also returned as a composite alarm: {described.get('CompositeAlarms')!r}"
    )

    cw.delete_alarms(AlarmNames=[alarm_name])

    described_after = cw.describe_alarms(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "CompositeAlarm", "LogAlarm"]
    )
    assert described_after.get("LogAlarms", []) == [], (
        f"log alarm {alarm_name} still present after DeleteAlarms: {described_after.get('LogAlarms')!r}"
    )
    assert described_after.get("MetricAlarms", []) == [], (
        f"unexpected metric alarm entry after DeleteAlarms: {described_after.get('MetricAlarms')!r}"
    )
    assert described_after.get("CompositeAlarms", []) == [], (
        f"unexpected composite alarm entry after DeleteAlarms: {described_after.get('CompositeAlarms')!r}"
    )
    del log_group_name  # kept for readability of _create_log_group return signature


def _safe(fn):
    """Best-effort cleanup: the resource may already have been deleted by the check
    body itself, and DeleteAlarms is not idempotent (raises ResourceNotFound for an
    already-deleted alarm), so swallow errors here."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _create_log_group(ctx):
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    name = ctx.unique_name("/sim2real/cw-log-alarm-")
    logs.create_log_group(logGroupName=name, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    account_id = sts.get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"
    return arn, name


def _create_scheduled_query_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwla-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-scheduled-query-exec",
        PolicyDocument=json.dumps(_QUERY_EXECUTION_POLICY),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-scheduled-query-exec"))
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(1)
    return role["Role"]["Arn"]


def _retry_on_error(fn, attempts=6, delay_s=5.0):
    """IAM role/policy propagation is eventually consistent; retry the dependent call
    a bounded number of times before giving up."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - deliberately broad, re-raised below
            last_exc = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
