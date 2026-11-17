"""update-user-pool-client-token-validity-unit-enum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-client-token-validity-unit-enum-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_ENUM_ERROR = (
    "InvalidParameterException",
    "1 validation error detected: Value 'weeks' at 'tokenValidityUnits.accessToken' failed to "
    "satisfy constraint: Member must satisfy enum value set: [hours, days, minutes, seconds]",
)


def _expect_error(fn, code: str, message: str) -> None:
    try:
        result = fn()
    except ClientError as exc:
        actual = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert actual == (code, message), f"expected {(code, message)!r}, got {actual!r}"
        return
    raise AssertionError(f"expected the call to be refused with {(code, message)!r}, got {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateUserPoolClient with a TokenValidityUnits value outside its enum fails with
    InvalidParameterException and its exact message, leaving the prior valid unit in place."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-")
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )

    # Positive control: a valid unit is accepted and persists.
    c.update_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id, TokenValidityUnits={"AccessToken": "hours"}
    )
    before = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert before.get("TokenValidityUnits") == {"AccessToken": "hours"}, (
        f"the positive control did not persist TokenValidityUnits.AccessToken='hours': {before!r}"
    )

    _expect_error(
        lambda: c.update_user_pool_client(
            UserPoolId=pool_id, ClientId=client_id, TokenValidityUnits={"AccessToken": "weeks"}
        ),
        *_ENUM_ERROR,
    )

    after = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert after.get("TokenValidityUnits") == {"AccessToken": "hours"}, (
        f"a rejected enum value must leave TokenValidityUnits at the prior valid setting, got "
        f"{after.get('TokenValidityUnits')!r}"
    )

    # Positive control after: the client is not wedged; a different valid unit still lands.
    c.update_user_pool_client(
        UserPoolId=pool_id, ClientId=client_id, TokenValidityUnits={"AccessToken": "days"}
    )
    reused = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"]
    assert reused.get("TokenValidityUnits") == {"AccessToken": "days"}, (
        f"the client could not be updated to a valid unit after the rejection: {reused!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
