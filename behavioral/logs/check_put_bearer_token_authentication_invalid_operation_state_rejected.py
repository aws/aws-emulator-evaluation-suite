"""put-bearer-token-authentication-invalid-operation-state-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-bearer-token-authentication-invalid-operation-state-rejected"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication on a missing log group is ResourceNotFoundException for both
    enable and disable and for a full-ARN identifier; enabling by ARN on an existing group succeeds
    and DescribeLogGroups reports bearerTokenAuthenticationEnabled=True."""
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bogus_log_group = ctx.unique_name("sim2real-behav-bearerinv-missing-")

    enable_code, enable_msg = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=bogus_log_group, bearerTokenAuthenticationEnabled=True
        )
    )
    assert enable_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException enabling bearer token auth on a missing log "
        f"group, got {enable_code!r}"
    )
    assert enable_msg == "The specified log group does not exist.", f"got {enable_msg!r}"

    disable_code, disable_msg = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=bogus_log_group, bearerTokenAuthenticationEnabled=False
        )
    )
    assert disable_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException disabling bearer token auth on a missing log "
        f"group too (not just the enable direction), got {disable_code!r}"
    )
    assert disable_msg == "The specified log group does not exist.", f"got {disable_msg!r}"

    bogus_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{bogus_log_group}"
    arn_code, arn_msg = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=bogus_arn, bearerTokenAuthenticationEnabled=True
        )
    )
    assert arn_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a fully-qualified but nonexistent log group "
        f"ARN identifier too, got {arn_code!r}"
    )
    assert arn_msg == "The specified log group does not exist.", f"got {arn_msg!r}"

    # Positive control: the same ARN-identifier call succeeds once the log group exists.
    real_log_group = ctx.unique_name("sim2real-behav-bearerinv-real-")
    logs.create_log_group(logGroupName=real_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))

    real_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{real_log_group}"
    logs.put_bearer_token_authentication(
        logGroupIdentifier=real_arn, bearerTokenAuthenticationEnabled=True
    )

    resp = logs.describe_log_groups(logGroupNamePrefix=real_log_group)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == real_log_group]
    assert len(matches) == 1 and matches[0]["bearerTokenAuthenticationEnabled"] is True, (
        f"expected bearerTokenAuthenticationEnabled=True on {real_log_group} after enabling by "
        f"ARN on an existing log group, got {matches}"
    )


def _error(fn):
    """Call fn(); return its botocore (error code, error message). An unexpected success raises,
    so a target accepting an unresolvable identifier is not reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call for an unresolvable log group, but it SUCCEEDED and "
        f"returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
