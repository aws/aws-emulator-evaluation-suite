"""put-log-alarm-limit-exceeded-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-log-alarm-limit-exceeded-enforced"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch"]

# "Maximum Log Alarms per account" -- fixed, non-adjustable quota (limited by the
# underlying CloudWatch Logs AWS-managed Scheduled Query quota).
_QUOTA = 1000


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError("expected the call to be rejected server-side, but it succeeded")


def _raw_client(ctx, service: str):
    """A client with client-side parameter validation disabled, so an omitted required
    field is sent and the service's rejection is observed, instead of boto3 raising a local
    ParamValidationError before any request is made.
    """
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutLogAlarm without Threshold (client-side validation off) is rejected server-side with
    ValidationError "1 validation error detected: Value null at 'threshold' ..." and creates no alarm, and
    the account's log-alarm count is below the fixed 1,000 quota at which PutLogAlarm refuses every alarm."""
    cw = ctx.client("cloudwatch")
    raw = _raw_client(ctx, "cloudwatch")

    alarm_name = ctx.unique_name("sim2real-behav-logalarm-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    account = ctx.client("sts").get_caller_identity()["Account"]
    # Every required member except Threshold is supplied, so exactly one null-member violation
    # is reported (with several missing members the service lists them in no stable order).
    # The role ARN is never dereferenced: the null-member refusal happens first.
    error = _client_error(
        lambda: raw.put_log_alarm(
            AlarmName=alarm_name,
            QueryResultsToEvaluate=5,
            QueryResultsToAlarm=3,
            ComparisonOperator="GreaterThanThreshold",
            ScheduledQueryConfiguration={
                "QueryString": "fields @timestamp | stats count() as cnt",
                "LogGroupIdentifiers": [ctx.unique_name("/sim2real/behav-logalarm-")],
                "ScheduledQueryRoleARN": f"arn:aws:iam::{account}:role/sim2real-behav-logalarm-none",
                "AggregationExpression": "count(*)",
                "ScheduleConfiguration": {"ScheduleExpression": "rate(5 minutes)", "StartTimeOffset": 360},
            },
        )
    )
    assert error.get("Code") == "ValidationError", f"expected ValidationError, got {error!r}"
    assert error.get("Message") == (
        "1 validation error detected: Value null at 'threshold' failed to satisfy constraint: "
        "Member must not be null"
    ), (
        f"unexpected message for an incomplete PutLogAlarm: {error.get('Message')!r}"
    )

    resp = cw.describe_alarms(AlarmNames=[alarm_name], AlarmTypes=["LogAlarm"])
    assert resp.get("LogAlarms", []) == [], "a rejected PutLogAlarm call must not create the alarm"

    current_count = _count_existing_log_alarms(cw)
    assert current_count < _QUOTA, (
        f"account already has {current_count} log alarms, at/above the documented, "
        f"non-adjustable quota of ~{_QUOTA}; PutLogAlarm should already be rejecting new "
        "log alarms with LimitExceededFault for this account"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
