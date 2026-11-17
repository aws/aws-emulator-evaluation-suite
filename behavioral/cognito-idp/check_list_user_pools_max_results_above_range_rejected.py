"""list-user-pools-max-results-above-range-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-user-pools-max-results-above-range-rejected"
GROUP = "validation"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListUserPools accepts MaxResults at its documented ceiling of 60 and rejects 61 with
    InvalidParameterException and its exact message."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_POOL_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    # Positive control: the documented ceiling itself is accepted.
    at_ceiling = idp.list_user_pools(MaxResults=60)
    assert "UserPools" in at_ceiling, f"expected a UserPools list at MaxResults=60, got {at_ceiling!r}"

    code, message = _error(lambda: idp.list_user_pools(MaxResults=61))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected = "1 validation error detected: Value '61' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 60"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
