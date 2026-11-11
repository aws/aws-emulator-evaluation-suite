"""scheduled-query-history-after-create."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "scheduled-query-history-after-create"
GROUP = "state-machine"
SERVICES = ["logs"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control",
      "timing:real-time")
def run(ctx) -> None:
    """GetScheduledQueryHistory returns execution records associated with a created,
    frequently-firing scheduled query once CloudWatch Logs has triggered it at least once."""

    logs = ctx.client("logs")
    log_group_name, log_group_arn = _create_log_group(ctx)
    role_arn = _create_execution_role(ctx)

    name = ctx.unique_name("sim2real-sqh-")
    query_string = "fields @timestamp, @message | limit 5"
    # Minute-level cron precision: fires every minute so history should populate quickly.
    schedule_expression = "cron(* * * * ? *)"

    created = _create_scheduled_query_with_retry(
        logs, name, query_string, schedule_expression, role_arn, log_group_arn, start_time_offset=60
    )
    sq_arn = created["scheduledQueryArn"]
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_scheduled_query(identifier=sq_arn)))

    creation_time = time.time()
    start_time = int(creation_time) - 60
    terminal = _poll_until(
        lambda: [
            h
            for h in logs.get_scheduled_query_history(
                identifier=sq_arn, startTime=start_time, endTime=int(time.time()) + 60
            )["triggerHistory"]
            if h["executionStatus"] != "Running"
        ],
        lambda h: len(h) > 0,
        timeout_s=200.0,
        interval_s=10.0,
    )
    if not terminal:
        raise AssertionError(
            "scheduled query did not reach a terminal executionStatus in "
            "GetScheduledQueryHistory within the poll window"
        )

    entry = terminal[0]
    now = time.time()
    # A well-formed query against a log group the execution role can read completes
    # cleanly; the full enum (which also includes InvalidQuery/Failed/Timeout) would
    # accept a target that never actually ran the query, so this pins the happy-path
    # outcome specifically.
    assert entry["executionStatus"] == "Complete", (
        f"expected a well-formed scheduled query to reach executionStatus 'Complete', "
        f"got {entry['executionStatus']!r} (entry={entry})"
    )
    assert start_time - 5 <= entry["triggeredTimestamp"] <= now + 5, (
        f"triggeredTimestamp {entry['triggeredTimestamp']} outside the expected window "
        f"[{start_time - 5}, {now + 5}]"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_log_group(ctx):
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=name)))
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{name}"
    return name, arn


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-sqhrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                # Trust both plausible service principals for scheduled-query execution: the
                # CloudWatch Logs service itself, and the underlying scheduler it may delegate
                # to. A too-narrow trust policy here would produce a persistent (not merely
                # propagation-delayed) AccessDeniedException when CreateScheduledQuery tries to
                # assume the role.
                "Principal": {"Service": ["logs.amazonaws.com", "scheduler.amazonaws.com"]},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="allow-query",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        # CreateScheduledQuery's docs say the execution role "must have
                        # permissions to read from the specified log groups" -- StartQuery /
                        # GetQueryResults / StopQuery alone were observed to persistently (not
                        # transiently) draw AccessDeniedException/ValidationException on real
                        # AWS, well past any plausible IAM propagation delay, which means the
                        # role's permission set itself was the problem, not eventual
                        # consistency. Grant the broader set of read actions that scheduled
                        # query execution needs to resolve and read the target log groups.
                        "Action": [
                            "logs:StartQuery",
                            "logs:GetQueryResults",
                            "logs:StopQuery",
                            "logs:DescribeLogGroups",
                            "logs:DescribeLogStreams",
                            "logs:GetLogEvents",
                            "logs:FilterLogEvents",
                        ],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="allow-query"))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _create_scheduled_query_with_retry(
    logs, name, query_string, schedule_expression, role_arn, log_group_arn, start_time_offset,
    timeout_s=90.0, interval_s=10.0,
):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return logs.create_scheduled_query(
                name=name,
                queryLanguage="CWLI",
                queryString=query_string,
                scheduleExpression=schedule_expression,
                executionRoleArn=role_arn,
                logGroupIdentifiers=[log_group_arn],
                startTimeOffset=start_time_offset,
                tags={"sim2real": CHECK},
            )
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] not in ("AccessDeniedException", "ValidationException"):
                raise
            time.sleep(interval_s)
    raise AssertionError(f"CreateScheduledQuery never succeeded (role propagation?): {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
