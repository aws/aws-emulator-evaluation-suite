"""create-scheduled-query-duplicate-name-conflict-fails."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-scheduled-query-duplicate-name-conflict-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateScheduledQuery rejects a second call using a name that already exists with
    ConflictException, instead of silently overwriting the existing scheduled query."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-schedq-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    role_arn = _create_scheduled_query_role(ctx)

    query_name = ctx.unique_name("sim2real-behav-schedqname-")
    original_query = "fields @timestamp, @message | limit 10"
    # startTimeOffset is a required field: it is a positive integer number of seconds
    # specifying how far back from each scheduled run time the query window starts (the
    # API rejects both an ISO-8601 duration string and a negative number here with
    # "StartTimeOffset must be a positive number").
    def _create_original():
        return logs.create_scheduled_query(
            name=query_name,
            queryLanguage="CWLI",
            queryString=original_query,
            scheduleExpression="cron(0 12 * * ? *)",
            executionRoleArn=role_arn,
            logGroupIdentifiers=[log_group],
            startTimeOffset=3600,
        )

    # The just-created execution role can take a few seconds to propagate through IAM;
    # retry through that eventual-consistency window instead of assuming it's instant.
    _retry_on_code(_create_original, "ResourceNotFoundException", attempts=10, delay_s=3)
    ctx.on_cleanup(lambda: logs.delete_scheduled_query(identifier=query_name))
    code, msg = _error(
        lambda: logs.create_scheduled_query(
            name=query_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp | limit 1",
            scheduleExpression="cron(0 0 * * ? *)",
            executionRoleArn=role_arn,
            logGroupIdentifiers=[log_group],
            startTimeOffset=3600,
        )
    )
    assert code == "ConflictException", (
        f"expected ConflictException when creating a scheduled query with a name that already "
        f"exists, got {code!r} {msg!r}"
    )
    assert msg == f"Scheduled query with identifier {query_name} already exists", (
        f"unexpected duplicate-name CreateScheduledQuery message: {msg!r}"
    )

    # The original scheduled query must be untouched by the rejected duplicate attempt.
    current = logs.get_scheduled_query(identifier=query_name)
    assert current["queryString"] == original_query, (
        "a rejected duplicate CreateScheduledQuery call must not overwrite the existing query"
    )


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises; a success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_on_code(fn, code: str, *, attempts: int = 5, delay_s: float = 2.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != code:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _create_scheduled_query_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-schedqrole-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:StartQuery", "logs:GetQueryResults", "logs:GetLogEvents"],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="scheduled-query-exec", PolicyDocument=json.dumps(inline_policy)
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="scheduled-query-exec")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
