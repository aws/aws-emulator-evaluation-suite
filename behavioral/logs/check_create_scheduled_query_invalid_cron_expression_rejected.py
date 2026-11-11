"""create-scheduled-query-invalid-cron-expression-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-scheduled-query-invalid-cron-expression-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScheduledQuery rejects a malformed cron expression as invalid input,
    the scheduled query is never created, and a well-formed cron expression still
    succeeds for the same execution role."""
    logs = ctx.client("logs")
    role_arn = _create_execution_role(ctx)

    group_name = ctx.unique_name("sim2real-behav-csq-lg-")
    logs.create_log_group(
        logGroupName=group_name,
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))

    bad_name = ctx.unique_name("sim2real-behav-csq-bad-")
    # A valid AWS cron expression needs 6 fields (min hour day-of-month month
    # day-of-week year); this one only has 4 and is not a valid rate() either.
    malformed_cron = "cron(0 12 * *)"

    code, message = _error(
        lambda: logs.create_scheduled_query(
            name=bad_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp | limit 1",
            scheduleExpression=malformed_cron,
            executionRoleArn=role_arn,
            logGroupIdentifiers=[group_name],
            startTimeOffset=3600,
            endTimeOffset=0,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    expected = (
        "1 validation errors detected: Invalid cron expression format. "
        "Expected format: cron(minutes hours day_of_month month day_of_week year)"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: no scheduled query with that name exists
    code, message = _error(lambda: logs.get_scheduled_query(identifier=bad_name))
    assert code == "ResourceNotFoundException", (
        f"the rejected CreateScheduledQuery must leave no scheduled query named {bad_name!r} "
        f"behind, got {code} from GetScheduledQuery"
    )
    expected = f"Scheduled query with identifier {bad_name} not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (c) positive control: a well-formed cron expression with the same execution
    # role is accepted.
    good_name = ctx.unique_name("sim2real-behav-csq-good-")
    good_cron = "cron(0 12 * * ? *)"
    # The execution role just created can take a few seconds to propagate through IAM;
    # retry through that eventual-consistency window instead of assuming it's instant.
    resp = _retry_on_codes(
        lambda: logs.create_scheduled_query(
            name=good_name,
            queryLanguage="CWLI",
            queryString="fields @timestamp | limit 1",
            scheduleExpression=good_cron,
            executionRoleArn=role_arn,
            logGroupIdentifiers=[group_name],
            startTimeOffset=3600,
            endTimeOffset=0,
            tags={"sim2real": CHECK},
        ),
        ("ResourceNotFoundException", "AccessDeniedException"),
        attempts=10,
        delay_s=3,
    )
    ctx.on_cleanup(lambda: logs.delete_scheduled_query(identifier=good_name))
    assert resp["scheduledQueryArn"], (
        "CreateScheduledQuery with a well-formed cron expression must return a scheduledQueryArn"
    )
    got = logs.get_scheduled_query(identifier=good_name)
    assert got["scheduleExpression"] == good_cron, (
        f"expected the well-formed cron {good_cron!r} to be stored verbatim, got "
        f"{got['scheduleExpression']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_on_codes(fn, codes, *, attempts: int = 5, delay_s: float = 2.0):
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in codes:
                raise
            last_exc = exc
            time.sleep(delay_s)
    raise last_exc


def _create_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-csq-role-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:StartQuery",
                    "logs:GetQueryResults",
                    "logs:DescribeLogGroups",
                ],
                "Resource": "*",
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="scheduled-query-exec",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="scheduled-query-exec")
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
