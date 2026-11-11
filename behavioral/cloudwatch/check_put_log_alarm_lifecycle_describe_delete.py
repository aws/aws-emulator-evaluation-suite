"""put-log-alarm-lifecycle-describe-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-alarm-lifecycle-describe-delete"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A log-based alarm created via PutLogAlarm appears via DescribeAlarms(AlarmTypes=['LogAlarm'])
    and is fully removed after DeleteAlarms."""
    cw = ctx.client("cloudwatch")
    logs = ctx.client("logs")
    iam = ctx.client("iam")

    put_log_alarm = _require_op(cw, "PutLogAlarm")

    log_group_name = ctx.unique_name("/sim2real/behavioral/logalarm-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _swallow(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]

    role_name = ctx.unique_name("sim2real-logalarm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cloudwatch.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-logalarm-query-policy"
    # Scope the query-execution actions (StartQuery/StopQuery/GetQueryResults) to the
    # log-group ARN. CloudWatch Logs' DescribeLogGroups response already returns the ARN
    # with a trailing ":*" (e.g. "arn:aws:logs:region:acct:log-group:name:*"); blindly
    # appending another ":*" produces "...:name:*:*", which does not match the actual
    # resource and makes every action AccessDenied regardless of IAM propagation time.
    # Normalize the ARN first, then list both the bare group ARN and its ":*" form so
    # the policy matches irrespective of which resource form a given action expects.
    #
    # logs:DescribeLogGroups does NOT support resource-level permissions at all -- it is
    # a list/describe action that only ever matches the "*" resource. A statement that
    # scopes it to a specific log-group ARN never matches, so that action is silently
    # denied by the implicit-deny default no matter how long IAM propagation is given.
    # CloudWatch calls DescribeLogGroups (to validate/resolve the configured log group)
    # when it runs the scheduled query, so this action needs its own "*"-resource
    # statement, separate from the ARN-scoped query actions.
    normalized_arn = log_group_arn[:-2] if log_group_arn.endswith(":*") else log_group_arn
    perm_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:StartQuery", "logs:StopQuery", "logs:GetQueryResults"],
                "Resource": [normalized_arn, f"{normalized_arn}:*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:DescribeLogGroups"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(perm_policy))
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))

    alarm_name = ctx.unique_name("sim2real-log-alarm-")
    last_code = [None]

    def _try_create() -> bool:
        try:
            put_log_alarm(
                AlarmName=alarm_name,
                AlarmDescription="sim2real behavioral fidelity check",
                ScheduledQueryConfiguration={
                    "QueryString": "fields @timestamp | stats count() as cnt",
                    # LogGroupIdentifiers expects log group ARNs *without* the trailing
                    # ":*" that DescribeLogGroups returns (that suffix is only meaningful
                    # for IAM resource-matching, e.g. in the role policy built below).
                    # Passing the ":*"-suffixed ARN here causes CloudWatch to reject the
                    # request with a permanent ValidationError on every attempt,
                    # regardless of IAM propagation delay -- use the normalized ARN.
                    "LogGroupIdentifiers": [normalized_arn],
                    "ScheduledQueryRoleARN": role["Arn"],
                    "AggregationExpression": "count(*)",
                    # StartTimeOffset is the offset (in seconds) applied to the schedule's
                    # evaluation time to compute the start of the query's look-back window, and
                    # the service models it as a non-negative value (the window starts this many
                    # seconds *before* "now"); a negative value fails botocore's own client-side
                    # parameter-range validation before any request is even sent to AWS, which is
                    # a permanent failure that no amount of retrying can fix. The service also
                    # server-side-validates that the offset must be strictly greater than the
                    # schedule's period (a value exactly equal to the 300s period of "rate(5
                    # minutes)" is rejected with ValidationError -- there must be some slack beyond
                    # one full period so the query's look-back window always covers the prior
                    # evaluation). Use 360 (> 300) to match the shape used successfully by the
                    # PutLogAlarm name-conflict check.
                    "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
                },
                QueryResultsToEvaluate=5,
                QueryResultsToAlarm=3,
                Threshold=1000000.0,
                ComparisonOperator="GreaterThanThreshold",
                TreatMissingData="notBreaching",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        except ClientError as exc:
            last_code[0] = exc.response["Error"]["Code"]
            return False
        return True

    # Retry to absorb IAM role/policy propagation lag.
    created = _poll_until(_try_create, timeout_s=90, interval_s=5)
    assert created, f"PutLogAlarm never succeeded (last error code: {last_code[0]!r})"
    ctx.on_cleanup(lambda: _swallow(lambda: cw.delete_alarms(AlarmNames=[alarm_name])))

    def _visible_as_log_alarm() -> bool:
        resp = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
        return any(a["AlarmName"] == alarm_name for a in resp.get("LogAlarms", []))

    assert _poll_until(_visible_as_log_alarm, timeout_s=30, interval_s=3), (
        "created log alarm not visible via DescribeAlarms(AlarmTypes=['LogAlarm'])"
    )

    described = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    log_alarms = described.get("LogAlarms", [])
    assert len(log_alarms) == 1, f"expected exactly 1 log alarm named {alarm_name!r}, got {log_alarms!r}"
    alarm = log_alarms[0]
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", alarm
    assert alarm["Threshold"] == 1000000.0, alarm
    assert alarm["QueryResultsToEvaluate"] == 5, alarm
    assert alarm["QueryResultsToAlarm"] == 3, alarm
    assert alarm["AlarmArn"].startswith("arn:aws:cloudwatch:") and alarm_name in alarm["AlarmArn"], alarm
    assert alarm["ScheduledQueryConfiguration"]["ScheduledQueryRoleARN"] == role["Arn"], alarm

    # It should not show up as a metric or composite alarm.
    default_view = cw.describe_alarms(AlarmNames=[alarm_name])
    assert not default_view.get("MetricAlarms"), "log alarm unexpectedly returned as a metric alarm"
    assert not default_view.get("CompositeAlarms"), "log alarm unexpectedly returned as a composite alarm"

    cw.delete_alarms(AlarmNames=[alarm_name])

    def _gone() -> bool:
        resp = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
        return not resp.get("LogAlarms")

    assert _poll_until(_gone, timeout_s=30, interval_s=3), "log alarm still present after DeleteAlarms"


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


def _poll_until(probe, timeout_s: float = 30.0, interval_s: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            if probe():
                return True
        except Exception:
            pass
        time.sleep(interval_s)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
