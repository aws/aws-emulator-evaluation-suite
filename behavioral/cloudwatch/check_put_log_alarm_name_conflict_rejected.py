"""put-log-alarm-name-conflict-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "put-log-alarm-name-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm reusing the name of an existing metric alarm is rejected with ValidationError."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    put_log_alarm = _require_op(cw, "PutLogAlarm")

    log_group_name = ctx.unique_name("/sim2real/behavioral/logalarm-conflict-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # DescribeLogGroups returns the ARN with a trailing ":*"; LogGroupIdentifiers refuses that
    # suffix with its own ValidationError, which would mask the alarm-name conflict under test.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    role_name = ctx.unique_name("sim2real-logalarm-conflict-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-logalarm-conflict-query-policy"
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults", "logs:DescribeLogGroups"],
                "Resource": f"{log_group_arn}:*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy))
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    # Create a plain metric alarm first, then try to reuse its name for a log alarm.
    alarm_name = ctx.unique_name("sim2real-conflict-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="Sim2RealBehavioral/Conflict",
        MetricName="ConflictMetric",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    def _attempt():
        return _client_error(
            lambda: put_log_alarm(
                AlarmName=alarm_name,
                ScheduledQueryConfiguration={
                    "QueryString": "fields @timestamp | stats count() as cnt",
                    "LogGroupIdentifiers": [log_group_arn],
                    "ScheduledQueryRoleARN": role["Arn"],
                    "AggregationExpression": "count(*)",
                    "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
                },
                QueryResultsToEvaluate=5,
                QueryResultsToAlarm=3,
                Threshold=1000000.0,
                ComparisonOperator="GreaterThanThreshold",
                TreatMissingData="notBreaching",
            )
        )

    # Retry a bit to absorb transient IAM-propagation AccessDenied noise before asserting on the
    # real conflict semantics.
    error = {}
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        error = _attempt()
        if error.get("Code") == "ValidationError":
            break
        time.sleep(5)

    assert error.get("Code") == "ValidationError", (
        f"expected ValidationError when reusing a metric alarm's name for a log alarm, got {error!r}"
    )
    assert error.get("Message") == f"AlarmName [{alarm_name}] is already used by another alarm of a different type", (
        f"unexpected message for the alarm-name conflict: {error.get('Message')!r}"
    )

    # The forbidden effect must be absent too: an independent read (DescribeAlarms, not the
    # rejected PutLogAlarm's own response) must show the original metric alarm untouched and no
    # log alarm created under the reused name.
    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm", "LogAlarm"])
    metric_alarms = described.get("MetricAlarms", [])
    assert len(metric_alarms) == 1, (
        f"expected the pre-existing metric alarm {alarm_name!r} to survive the rejected "
        f"PutLogAlarm, found {len(metric_alarms)} metric alarms with that name"
    )
    surviving = metric_alarms[0]
    assert surviving["Namespace"] == "Sim2RealBehavioral/Conflict", (
        "surviving metric alarm's namespace changed: expected 'Sim2RealBehavioral/Conflict', "
        f"got {surviving['Namespace']!r}"
    )
    assert surviving["MetricName"] == "ConflictMetric", (
        f"surviving metric alarm's metric name changed: expected 'ConflictMetric', got {surviving['MetricName']!r}"
    )
    assert described.get("LogAlarms", []) == [], (
        f"a log alarm was created under {alarm_name!r} despite the rejected PutLogAlarm: "
        f"{described.get('LogAlarms')}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _swallow(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchEntity",
            "ResourceNotFound",
            "ResourceNotFoundException",
        ):
            raise


def _bound_method(client, operation_name):
    mapping = getattr(client.meta, "method_to_api_mapping", {})
    for method_name, op in mapping.items():
        if op == operation_name:
            return getattr(client, method_name)
    return None


def _require_op(client, operation_name):
    fn = _bound_method(client, operation_name)
    if fn is None:
        raise AssertionError(f"botocore in this environment has no operation {operation_name}")
    return fn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
