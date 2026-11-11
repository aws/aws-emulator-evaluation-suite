"""token-validity-out-of-range-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "token-validity-out-of-range-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolClient with a 25-hour AccessTokenValidity fails with InvalidParameterException and its
    exact message and leaves the 24-hour value, while the same call with 1 hour is applied."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"))["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    # Positive control: the boundary value itself, 24h, is accepted and persists.
    c.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        AccessTokenValidity=24,
        TokenValidityUnits={"AccessToken": "hours"},
    )
    before = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert before.get("AccessTokenValidity") == 24 and before.get("TokenValidityUnits", {}).get("AccessToken") == "hours", (
        f"the positive control did not persist AccessTokenValidity=24h: {before!r}"
    )

    error = _client_error(lambda: c.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        AccessTokenValidity=25,
        TokenValidityUnits={"AccessToken": "hours"},
    ))
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException for AccessTokenValidity=25h, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Invalid range for token validity.", (
        f"expected the exact out-of-range AccessTokenValidity message, got {error.get('Message')!r}"
    )

    # Effect absent: an independent read proves the rejected 25h never took hold.
    after = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert after.get("AccessTokenValidity") == 24, (
        f"a rejected AccessTokenValidity=25h update must leave the client at the prior valid "
        f"value 24, got {after.get('AccessTokenValidity')}"
    )

    # Positive control after: the client is not wedged; a different valid value still lands.
    c.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        AccessTokenValidity=1,
        TokenValidityUnits={"AccessToken": "hours"},
    )
    reused = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert reused.get("AccessTokenValidity") == 1, (
        f"the client could not be updated to a valid value after the rejection: {reused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
