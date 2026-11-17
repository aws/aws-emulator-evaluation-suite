"""get-scheduled-query-history-nonexistent-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-scheduled-query-history-nonexistent-rejected"
GROUP = "error-semantics"
SERVICES = ["logs", "iam"]


def _expect_error(fn, code, message) -> None:
    """Call fn(); assert it raises exactly (code, message). Raises if fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err.get("Code") == code, f"expected code {code!r}, got {err!r}"
        assert err.get("Message") == message, f"expected message {message!r}, got {err.get('Message')!r}"
        return
    raise AssertionError(f"expected {code!r}, but the call succeeded: {result!r}")


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_query_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sqhrole-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "logs.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-behav-sqh-exec"
    exec_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:StartQuery", "logs:GetQueryResults"],
                    "Resource": "*",
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=exec_policy)
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _create_scheduled_query_retrying_propagation(logs, *, deadline_s: float = 60.0, **kwargs):
    """CreateScheduledQuery validates the execution role by assuming it, which can lag the
    role's own creation by a few seconds; retry on that specific propagation failure only."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return logs.create_scheduled_query(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScheduledQueryHistory on an identifier that was never created raises
    ResourceNotFoundException with its exact message, while the same call against a real
    scheduled query succeeds."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group)))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[:-2]

    role_arn = _create_query_role(ctx)

    query_name = ctx.unique_name("sim2real-behav-sq-")
    _create_scheduled_query_retrying_propagation(
        logs,
        name=query_name,
        queryLanguage="CWLI",
        queryString="fields @timestamp, @message | limit 1",
        scheduleExpression="cron(0 12 * * ? *)",
        executionRoleArn=role_arn,
        logGroupIdentifiers=[log_group_arn],
        state="ENABLED",
        startTimeOffset=3600,
    )
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_scheduled_query(identifier=query_name)))

    now_s = int(time.time())

    # Positive control: history for a real, just-created scheduled query is readable.
    real_history = logs.get_scheduled_query_history(
        identifier=query_name, startTime=now_s - 3600, endTime=now_s + 3600
    )
    assert real_history["name"] == query_name, (
        f"expected name {query_name!r} in GetScheduledQueryHistory, got {real_history.get('name')!r}"
    )

    # Negative: an identifier that was never created is rejected.
    missing_name = ctx.unique_name("sim2real-behav-sq-absent-")
    _not_found = (
        "ResourceNotFoundException",
        f"Scheduled query with identifier {missing_name} not found",
    )
    _expect_error(
        lambda: logs.get_scheduled_query_history(
            identifier=missing_name, startTime=now_s - 3600, endTime=now_s + 3600
        ),
        *_not_found,
    )

    # The real scheduled query's history is unaffected by the rejected call on a sibling name.
    still_there = logs.get_scheduled_query_history(
        identifier=query_name, startTime=now_s - 3600, endTime=now_s + 3600
    )
    assert still_there["name"] == query_name, (
        f"expected name {query_name!r} still readable after the rejected call, got "
        f"{still_there.get('name')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
