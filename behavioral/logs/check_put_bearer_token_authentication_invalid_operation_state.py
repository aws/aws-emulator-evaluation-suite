"""put-bearer-token-authentication-invalid-operation-state."""
from __future__ import annotations

CHECK = "put-bearer-token-authentication-invalid-operation-state"
GROUP = "error-semantics"
SERVICES = ["logs"]

from behavioral_harness import tags


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBearerTokenAuthentication enables bearer token authentication on an existing group, and the
    same call on a group that cannot be resolved is refused with ResourceNotFoundException and its
    exact message.
    """
    logs = ctx.client("logs")

    # Positive control: the same call, against a log group that DOES exist, must succeed and
    # the flag must be independently observable via DescribeLogGroups -- not merely echoed back
    # by the write, whose response body is empty. Without this leg, the negative below cannot
    # be told apart from "PutBearerTokenAuthentication is rejected unconditionally".
    real_log_group = ctx.unique_name("sim2real-bearertoken-real-lg-")
    logs.create_log_group(logGroupName=real_log_group)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=real_log_group))

    logs.put_bearer_token_authentication(
        logGroupIdentifier=real_log_group, bearerTokenAuthenticationEnabled=True
    )

    resp = logs.describe_log_groups(logGroupNamePrefix=real_log_group)
    matches = [g for g in resp["logGroups"] if g["logGroupName"] == real_log_group]
    assert len(matches) == 1, f"expected exactly one log group named {real_log_group!r}, got {len(matches)}"
    assert matches[0]["bearerTokenAuthenticationEnabled"] is True, (
        f"expected bearerTokenAuthenticationEnabled=True via an independent DescribeLogGroups "
        f"read, got {matches[0].get('bearerTokenAuthenticationEnabled')!r}"
    )

    # Negative: the same call against a log group identifier that cannot be resolved at all.
    bogus_log_group = ctx.unique_name("sim2real-bearertoken-missing-lg-")
    code, msg = _error(lambda: logs.put_bearer_token_authentication(
        logGroupIdentifier=bogus_log_group, bearerTokenAuthenticationEnabled=True
    ))
    assert code == "ResourceNotFoundException", f"got {code!r}"
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
