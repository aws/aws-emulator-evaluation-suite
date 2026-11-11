"""put-bearer-token-authentication-invalid-config-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-bearer-token-authentication-invalid-config-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication on a nonexistent log group is refused with ResourceNotFoundException
    and its exact message, while the same call on a real group enables bearer token authentication.
    """
    logs = ctx.client("logs")

    # Positive control: the same call, same shape, against a log group that exists.
    real_group = ctx.unique_name("sim2real-behav-bearercfg-")
    logs.create_log_group(logGroupName=real_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_group))

    logs.put_bearer_token_authentication(
        logGroupIdentifier=real_group,
        bearerTokenAuthenticationEnabled=True,
    )

    resp = logs.describe_log_groups(logGroupNamePrefix=real_group)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == real_group]
    assert len(matches) == 1 and matches[0]["bearerTokenAuthenticationEnabled"] is True, (
        f"expected {real_group} to show bearerTokenAuthenticationEnabled=True via an "
        f"independent DescribeLogGroups read, got {matches}"
    )

    # Break exactly the one precondition (existence) and assert the specific rejection.
    bogus_group = ctx.unique_name("sim2real-behav-notexist-")
    code, msg = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=bogus_group,
            bearerTokenAuthenticationEnabled=True,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException enabling bearer token auth on a missing "
        f"log group, got {code!r}"
    )
    assert msg == "The specified log group does not exist.", f"got {msg!r}"


def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a mere mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
