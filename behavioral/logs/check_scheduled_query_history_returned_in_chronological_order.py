"""scheduled-query-history-returned-in-chronological-order."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "scheduled-query-history-returned-in-chronological-order"
GROUP = "ordering"
SERVICES = ["logs"]


# timing:real-time — schedule: 60 s
@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """GetScheduledQueryHistory returns execution records ordered by run time (monotonic
    triggeredTimestamp), not shuffled insertion order."""
    logs = ctx.client("logs")

    log_group_name, log_group_arn = _create_log_group(ctx, "sim2real-behav-sqlg-")
    role_name, role_arn = _create_execution_role(ctx)
    _attach_execution_policy(ctx, role_name)

    query_name = ctx.unique_name("sim2real-behav-sqh-")
    start_time = int(time.time()) - 60
    _create_scheduled_query_with_retry(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 1",
        scheduleExpression="cron(0/1 * * * ? *)",
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_arn],
        state="ENABLED",
        startTimeOffset=3600,
        tags={"Sim2RealOwner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_scheduled_query(identifier=query_name)))

    def _probe():
        return logs.get_scheduled_query_history(
            identifier=query_name, startTime=start_time, endTime=int(time.time()) + 1
        ).get("triggerHistory", [])

    history = _poll_until(_probe, lambda h: len(h) >= 3, timeout_s=420.0, interval_s=20.0)
    if len(history) < 3:
        raise AssertionError(
            f"scheduled query only accumulated {len(history)} execution(s) within the poll "
            "window; not enough history to assert ordering"
        )

    timestamps = [rec["triggeredTimestamp"] for rec in history]
    ascending = sorted(timestamps)
    descending = sorted(timestamps, reverse=True)
    assert timestamps == ascending or timestamps == descending, (
        f"triggerHistory is not chronologically ordered: {timestamps}"
    )
    # Sanity: the timestamps must actually be distinct execution times, not a degenerate
    # constant list that would trivially satisfy the sortedness check above.
    assert len(set(timestamps)) >= 2, f"expected distinct trigger times, got {timestamps}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    return None


def _safe_call(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException",):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_log_group(ctx, prefix: str):
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=name)))
    resp = logs.describe_log_groups(logGroupNamePrefix=name)
    arn = resp["logGroups"][0]["arn"]
    # DescribeLogGroups returns the ARN with a trailing ":*" (a legacy artifact). APIs that
    # take a log group identifier as an ARN -- such as CreateScheduledQuery's
    # logGroupIdentifiers -- validate against a pattern that rejects that suffix, so it must
    # be stripped before use.
    if arn.endswith(":*"):
        arn = arn[:-2]
    return name, arn


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sqrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "scheduled-query-history-chronological-order"}],
    )
    role_arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: iam.delete_role(RoleName=role_name)))
    return role_name, role_arn


def _attach_execution_policy(ctx, role_name: str):
    iam = ctx.client("iam")
    policy_name = "sim2real-behav-sq-exec-policy"
    doc = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    ctx.on_cleanup(
        lambda: _safe_call(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )


def _create_scheduled_query_with_retry(logs_client, retry_seconds: float = 60.0, **kwargs):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + retry_seconds
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return logs_client.create_scheduled_query(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ResourceNotFoundException"):
                last_exc = e
                time.sleep(3)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
