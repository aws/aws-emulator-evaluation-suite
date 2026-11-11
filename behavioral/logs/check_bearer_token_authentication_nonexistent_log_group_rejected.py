"""bearer-token-authentication-nonexistent-log-group-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bearer-token-authentication-nonexistent-log-group-rejected"
GROUP = "state-machine"
SERVICES = ["logs"]


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication on a non-existent log group is rejected; a real one succeeds."""
    logs = ctx.client("logs")
    missing_name = ctx.unique_name("sim2real-logs-bearer-missing-")

    # Negative: the target log group was never created.
    code, message = _error(
        lambda: logs.put_bearer_token_authentication(
            logGroupIdentifier=missing_name, bearerTokenAuthenticationEnabled=True
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "The specified log group does not exist."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # Positive control: break exactly the one precondition (existence) and show the identical
    # call succeeds once that precondition holds.
    real_name = ctx.unique_name("sim2real-logs-bearer-real-")
    logs.create_log_group(logGroupName=real_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_name))

    logs.put_bearer_token_authentication(
        logGroupIdentifier=real_name, bearerTokenAuthenticationEnabled=True
    )

    resp = logs.describe_log_groups(logGroupNamePrefix=real_name)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == real_name]
    assert len(matches) == 1 and matches[0]["bearerTokenAuthenticationEnabled"] is True, (
        f"expected exactly one log group named {real_name!r} with bearerTokenAuthenticationEnabled "
        f"True, got {matches!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
