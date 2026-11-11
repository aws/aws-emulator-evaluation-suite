"""put-log-alarm-resource-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "put-log-alarm-resource-conflict-rejected"
GROUP = "error-semantics"
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm on an AlarmName held by a metric alarm is rejected with ValidationError "AlarmName
    [<name>] is already used by another alarm of a different type", leaving the metric alarm and no log
    alarm; once the metric alarm is deleted the identical call succeeds and the log alarm is listed."""
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_log_alarm"):
        raise AssertionError("cloudwatch client lacks put_log_alarm; botocore predates the LogAlarm API")

    alarm_name = ctx.unique_name("sim2real-log-conflict-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2Real/Behavioral",
        MetricName="LogAlarmConflictMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    log_group_arn = _create_log_group(ctx)
    role_arn = _create_scheduled_query_role(ctx)

    config = {
        "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
        "LogGroupIdentifiers": [log_group_arn],
        "ScheduledQueryRoleARN": role_arn,
        "AggregationExpression": "count(*)",
        "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
    }

    def _attempt():
        return cw.put_log_alarm(
            AlarmName=alarm_name,
            ScheduledQueryConfiguration=config,
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
        )

    error = _client_error_with_retry(_attempt)
    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError while the metric alarm still holds the name, got {error!r}"
    )
    assert error.get("Message") == f"AlarmName [{alarm_name}] is already used by another alarm of a different type", (
        f"unexpected message for the alarm-name conflict: {error.get('Message')!r}"
    )

    # the original metric alarm must be untouched, and no log alarm exists under the name
    still_conflicting = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "LogAlarm"])
    assert len(still_conflicting.get("MetricAlarms", [])) == 1, (
        f"expected the original metric alarm to survive the rejected PutLogAlarm, got {still_conflicting.get('MetricAlarms')}"
    )
    assert still_conflicting.get("LogAlarms", []) == [], (
        f"expected no log alarm to have been created under the conflicting name, got {still_conflicting.get('LogAlarms')}"
    )

    # restore: remove the conflicting metric alarm, then the identical call must succeed
    cw.delete_alarms(AlarmNames=[alarm_name])
    _retry_until_conflict_clears(_attempt, alarm_name)

    resolved = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "LogAlarm"])
    assert resolved.get("MetricAlarms", []) == [], (
        f"expected the metric alarm to be gone after delete_alarms, got {resolved.get('MetricAlarms')}"
    )
    assert len(resolved.get("LogAlarms", [])) == 1, (
        f"expected the identical PutLogAlarm call to succeed once the name was free, got {resolved.get('LogAlarms')}"
    )


def _create_log_group(ctx):
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    name = ctx.unique_name("/sim2real/cw-log-conflict-")
    logs.create_log_group(logGroupName=name, tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    account_id = sts.get_caller_identity()["Account"]
    return f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"


def _create_scheduled_query_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cwlc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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


def _client_error_with_retry(fn, attempts=6, delay_s=5.0):
    """Retries only on non-conflict errors (IAM eventual consistency); a ValidationError
    conflict is deterministic and returned immediately. A SUCCESS raises AssertionError."""
    from botocore.exceptions import ClientError

    last_error = {}
    for attempt in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            error = exc.response["Error"]
            if error.get("Code") == "ValidationError":
                return error
            last_error = error
            if attempt < attempts - 1:
                time.sleep(delay_s)
            continue
        raise AssertionError(
            f"expected the name conflict to be rejected, but the call SUCCEEDED and returned {result!r}"
        )
    return last_error


def _retry_until_conflict_clears(fn, alarm_name, timeout_s=60.0, interval_s=5.0):
    """After deleting the conflicting metric alarm, the identical PutLogAlarm call must
    succeed once the delete has propagated. Retries only while it still reports the
    same name conflict (AlarmName index catching up); any other error is unexpected."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message")
            conflict = f"AlarmName [{alarm_name}] is already used by another alarm of a different type"
            if code != "ValidationError" or message != conflict or time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected the identical PutLogAlarm call to succeed once the conflicting "
                    f"metric alarm was deleted, got {code} ({message!r})"
                ) from exc
            time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
