"""delete-scheduled-query-nonexistent-fails."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-scheduled-query-nonexistent-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After a scheduled query is deleted, GetScheduledQuery and a second DeleteScheduledQuery raise
    ResourceNotFoundException with the exact message, as does deleting a never-created identifier."""
    logs = ctx.client("logs")

    log_group = ctx.unique_name("sim2real-behav-nosuchsq-")
    logs.create_log_group(logGroupName=log_group)
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_log_group(logGroupName=log_group)))

    role_arn = _create_scheduled_query_role(ctx)

    query_name = ctx.unique_name("sim2real-behav-nosuchsq-")

    def _create():
        return logs.create_scheduled_query(
            name=query_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp, @message | limit 1",
            scheduleExpression="cron(0 12 * * ? *)",
            executionRoleArn=role_arn,
            logGroupIdentifiers=[log_group],
            startTimeOffset=3600,
        )

    # The just-created execution role can take a few seconds to propagate through IAM.
    _retry_on_code(_create, "ResourceNotFoundException", attempts=10, delay_s=3)
    ctx.on_cleanup(lambda: _safe_call(lambda: logs.delete_scheduled_query(identifier=query_name)))

    # Positive control: DeleteScheduledQuery must succeed on a real, existing identifier.
    # Without this, a target that unconditionally rejects every DeleteScheduledQuery call
    # -- valid or not -- would still pass the negative assertions below.
    logs.delete_scheduled_query(identifier=query_name)
    error = _expect_error(lambda: logs.get_scheduled_query(identifier=query_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected the deleted scheduled query to be gone, got {error!r}"
    )
    expected_message = f"Scheduled query with identifier {query_name} not found"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # An identifier that existed and was already deleted must still be rejected by a
    # second delete, not silently accepted as a no-op.
    error = _expect_error(lambda: logs.delete_scheduled_query(identifier=query_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DeleteScheduledQuery on {query_name} "
        f"after it was already deleted, got {error!r}"
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # An identifier that never corresponded to any scheduled query must be rejected the
    # same way.
    missing_identifier = ctx.unique_name("sim2real-behav-nosuchsq-")
    error = _expect_error(lambda: logs.delete_scheduled_query(identifier=missing_identifier))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for DeleteScheduledQuery on an unknown "
        f"identifier, got {error!r}"
    )
    expected_message = f"Scheduled query with identifier {missing_identifier} not found"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )


def _expect_error(fn: Callable[[], Any]) -> dict:
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _safe_call(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _retry_on_code(fn: Callable[[], Any], code: str, *, attempts: int = 5, delay_s: float = 2.0):
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
    role_name = ctx.unique_name("sim2real-behav-nosuchsqrole-")
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
