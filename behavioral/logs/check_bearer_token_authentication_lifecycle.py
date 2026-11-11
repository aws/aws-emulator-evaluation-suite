"""bearer-token-authentication-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "bearer-token-authentication-lifecycle"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication enables (idempotently) and disables on an existing log group, each
    state confirmed by DescribeLogGroups, and is rejected for a log group that does not exist."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-bearer-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    # Enabling on a real log group must succeed with an empty response body,
    # and the flag must be durably observable via an independent read.
    logs.put_bearer_token_authentication(
        logGroupIdentifier=log_group_name, bearerTokenAuthenticationEnabled=True
    )
    assert _bearer_enabled(logs, log_group_name) is True, (
        "PutBearerTokenAuthentication(enabled=True) did not persist: "
        "DescribeLogGroups still reports it disabled"
    )

    # The server-side toggle is idempotent: enabling it again must not fail
    # or otherwise behave as a state conflict, and the flag must remain set.
    logs.put_bearer_token_authentication(
        logGroupIdentifier=log_group_name, bearerTokenAuthenticationEnabled=True
    )
    assert _bearer_enabled(logs, log_group_name) is True, (
        "re-enabling bearer token auth (idempotent call) flipped the observed state"
    )

    # Disabling it again must succeed and be observable as a genuine toggle,
    # not a permanent one-way switch.
    logs.put_bearer_token_authentication(
        logGroupIdentifier=log_group_name, bearerTokenAuthenticationEnabled=False
    )
    assert _bearer_enabled(logs, log_group_name) is False, (
        "PutBearerTokenAuthentication(enabled=False) did not persist: "
        "DescribeLogGroups still reports it enabled"
    )

    # The same server-side control cannot be enabled on a log group that does
    # not exist -- this is the resource boundary that distinguishes "enable
    # an auth mechanism" from a no-op success.
    bogus_log_group = ctx.unique_name("sim2real-behav-bearer-nonexistent-")
    code, message = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=bogus_log_group, bearerTokenAuthenticationEnabled=True
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException enabling bearer auth on an unknown log group, got {code!r}"
    )
    expected_message = "The specified log group does not exist."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _bearer_enabled(logs, log_group_name: str) -> bool:
    resp = logs.describe_log_groups(logGroupNamePrefix=log_group_name)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == log_group_name]
    assert len(matches) == 1, f"expected exactly one log group named {log_group_name!r}, got {matches!r}"
    return bool(matches[0]["bearerTokenAuthenticationEnabled"])


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
