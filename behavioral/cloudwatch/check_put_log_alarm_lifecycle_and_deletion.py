"""put-log-alarm-lifecycle-and-deletion."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-alarm-lifecycle-and-deletion"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm creates a log-based alarm visible via DescribeAlarms
    (AlarmTypes=[LogAlarm]); DeleteAlarms fully removes it."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    log_group_name = ctx.unique_name("sim2real-logalarm-lg-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: logs.delete_log_group(logGroupName=log_group_name))
    )
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0][
        "arn"
    ]
    # CloudWatch Logs returns log group ARNs with a trailing ":*" suffix, but
    # the scheduled-query logGroupIdentifiers validation pattern
    # ([\w#+=/:,.@-]+) does not permit "*", so PutLogAlarm rejects it as
    # invalid. Strip the suffix to get the ARN form the API actually accepts.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]


    role_name = ctx.unique_name("sim2real-logalarm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "logs.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
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

    def _cleanup_role() -> None:
        _ignore_errors(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        )
        _ignore_errors(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup_role)

    alarm_name = ctx.unique_name("sim2real-logalarm-")
    scheduled_query_configuration = {
        "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
        "LogGroupIdentifiers": [log_group_arn],
        "ScheduledQueryRoleARN": role_arn,
        "AggregationExpression": "count(*)",
        "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
    }

    # IAM role trust/permissions may need a few seconds to propagate.
    _retry(
        lambda: cw.put_log_alarm(
            AlarmName=alarm_name,
            AlarmDescription="sim2real behavioral check log alarm",
            ScheduledQueryConfiguration=scheduled_query_configuration,
            QueryResultsToAlarm=1,
            QueryResultsToEvaluate=1,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="notBreaching",
        ),
        timeout_s=45,
        interval_s=4,
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    )

    # 1. DescribeAlarms(AlarmTypes=[LogAlarm]) shows the new alarm.
    found = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"]),
        lambda resp: any(a["AlarmName"] == alarm_name for a in resp.get("LogAlarms", [])),
        timeout_s=20,
        interval_s=2,
    )
    log_alarm = next(a for a in found["LogAlarms"] if a["AlarmName"] == alarm_name)
    assert log_alarm["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected ComparisonOperator 'GreaterThanThreshold', got {log_alarm.get('ComparisonOperator')!r}"
    )
    assert log_alarm["ScheduledQueryConfiguration"]["ScheduledQueryRoleARN"] == role_arn, (
        f"expected ScheduledQueryRoleARN {role_arn!r}, got "
        f"{log_alarm['ScheduledQueryConfiguration'].get('ScheduledQueryRoleARN')!r}"
    )
    assert log_alarm["Threshold"] == 10.0, f"expected Threshold 10.0, got {log_alarm.get('Threshold')!r}"
    assert log_alarm["QueryResultsToAlarm"] == 1, (
        f"expected QueryResultsToAlarm 1, got {log_alarm.get('QueryResultsToAlarm')!r}"
    )
    assert log_alarm["QueryResultsToEvaluate"] == 1, (
        f"expected QueryResultsToEvaluate 1, got {log_alarm.get('QueryResultsToEvaluate')!r}"
    )
    assert log_alarm["AlarmArn"].startswith("arn:aws:cloudwatch:") and alarm_name in log_alarm["AlarmArn"], (
        f"expected AlarmArn for {alarm_name!r} under arn:aws:cloudwatch:, got {log_alarm.get('AlarmArn')!r}"
    )
    assert found.get("MetricAlarms", []) == [], (
        f"log alarm unexpectedly returned as a metric alarm: {found.get('MetricAlarms')!r}"
    )
    assert found.get("CompositeAlarms", []) == [], (
        f"log alarm unexpectedly returned as a composite alarm: {found.get('CompositeAlarms')!r}"
    )

    # 2. DeleteAlarms fully removes it.
    cw.delete_alarms(AlarmNames=[alarm_name])
    gone = _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"]),
        lambda resp: not resp.get("LogAlarms"),
        timeout_s=20,
        interval_s=2,
    )
    assert gone.get("LogAlarms", []) == [], (
        f"log alarm {alarm_name} still present after DeleteAlarms: {gone.get('LogAlarms')!r}"
    )


def _ignore_errors(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFound",
            "ResourceNotFoundException",
        ):
            raise


def _retry(fn: Callable[[], Any], *, timeout_s: float = 30.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    if last_exc:
        raise last_exc
    raise AssertionError("retry loop exited without success or exception")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 30.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
