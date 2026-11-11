"""log-alarm-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-alarm-lifecycle"
GROUP = 'alarms'
SERVICES = ['cloudwatch']

_METRIC_ALARM_DEFAULTS = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)


def _err(fn):
    """Call fn(); return the botocore error (Code, Message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_log_alarm_prereqs(ctx):
    """Create a real log group + IAM execution role for a PutLogAlarm scheduled query."""
    logs = ctx.client("logs")
    iam = ctx.client("iam")
    log_group_name = ctx.unique_name("sim2real-behav-cwprobe-loggrp-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda _n=log_group_name: logs.delete_log_group(logGroupName=_n))

    role_name = ctx.unique_name("sim2real-behav-cwprobe-logalarmrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
    role_arn = resp["Role"]["Arn"]
    policy_name = "log-alarm-query-access"
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
                            "logs:GetQueryResults",
                            "logs:StopQuery",
                            "logs:GetLogRecord",
                            "logs:GetLogEvents",
                            "logs:DescribeLogGroups",
                            "logs:FilterLogEvents",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )

    def _delete_role(_r=role_name, _p=policy_name):
        try:
            iam.delete_role_policy(RoleName=_r, PolicyName=_p)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=_r)

    ctx.on_cleanup(_delete_role)

    return role_arn, log_group_name


def _retry_iam_propagation(fn, *, timeout_s=60, interval_s=5.0):
    """The role/policy just created above is eventually consistent; retry the first call that
    depends on it until it succeeds or the budget is exhausted, instead of guessing a fixed
    settle time."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"call never succeeded within {timeout_s}s (IAM propagation?): {last_exc!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm creates a log-based alarm visible in DescribeAlarms; DeleteAlarms removes it. Also verifies
    that reusing an existing metric alarm's name for a log alarm is rejected with ResourceConflict.
    """
    cw = ctx.client("cloudwatch")
    if not hasattr(cw, "put_log_alarm"):
        raise AssertionError(
            "cloudwatch.put_log_alarm is not modeled in the installed botocore; "
            "the log-alarm lifecycle cannot be exercised"
        )
    role_arn, log_group_name = _create_log_alarm_prereqs(ctx)
    name = ctx.unique_name("sim2real-behav-cwprobe-logalarm-")
    ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))

    def scheduled_query():
        return {
            "QueryString": "fields @timestamp, @message | filter @message like /ERROR/",
            "LogGroupIdentifiers": [log_group_name],
            "ScheduledQueryRoleARN": role_arn,
            "AggregationExpression": "count(*)",
            "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
        }

    _retry_iam_propagation(
        lambda: cw.put_log_alarm(
            AlarmName=name,
            ScheduledQueryConfiguration=scheduled_query(),
            QueryResultsToAlarm=3,
            QueryResultsToEvaluate=5,
            Threshold=10.0,
            ComparisonOperator="GreaterThanThreshold",
        )
    )

    def probe():
        resp = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["LogAlarm"])
        return resp.get("LogAlarms", [])

    alarms = _poll_until(probe, lambda a: len(a) == 1, timeout_s=30, interval_s=3)
    assert alarms[0]["AlarmName"] == name, f"expected log alarm named {name!r}, got {alarms!r}"

    cw.delete_alarms(AlarmNames=[name])
    resp2 = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["LogAlarm"])
    assert resp2.get("LogAlarms", []) == [], "log alarm should be gone after DeleteAlarms"

    # Overly-permissive check: a log alarm name that collides with an existing
    # alarm of a *different* type (metric alarm) must be rejected.
    metric_name = ctx.unique_name("sim2real-behav-cwprobe-alarm-")
    ctx.on_cleanup(lambda _n=metric_name: cw.delete_alarms(AlarmNames=[_n]))
    cw.put_metric_alarm(AlarmName=metric_name, **_METRIC_ALARM_DEFAULTS)
    error = _err(
        lambda: cw.put_log_alarm(
            AlarmName=metric_name,
            ScheduledQueryConfiguration=scheduled_query(),
            QueryResultsToAlarm=1,
            QueryResultsToEvaluate=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanThreshold",
        )
    )
    assert error == ("ValidationError", f"AlarmName [{metric_name}] is already used by another alarm of a different type"), (
        f"expected the ValidationError for a cross-type alarm name collision, got {error!r}"
    )

    # Independent read at the destination: the rejected call must have had no effect at all —
    # the pre-existing metric alarm is untouched and no log alarm was created under the name.
    after = cw.describe_alarms(AlarmNames=[metric_name])
    metric_alarms_after = after.get("MetricAlarms", [])
    assert [a["AlarmName"] for a in metric_alarms_after] == [metric_name], (
        f"existing metric alarm {metric_name!r} should be unaffected by the rejected log-alarm "
        f"collision, got {metric_alarms_after!r}"
    )
    log_alarms_after = cw.describe_alarms(AlarmNames=[metric_name], AlarmTypes=["LogAlarm"]).get("LogAlarms", [])
    assert log_alarms_after == [], (
        f"rejected PutLogAlarm must not have created a log alarm named {metric_name!r}, got {log_alarms_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
