"""get-user-auth-factors-deleted-user-not-found-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-user-auth-factors-deleted-user-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetUserAuthFactors with a deleted user's still-valid access token fails with UserNotFoundException,
    as does AdminGetUser, each with its exact message, while another user's token still resolves."""
    cip = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)

    doomed_user = "hank"
    ok_user = "irene"
    password = "Sim2Real123"
    doomed_token = _create_confirmed_user_and_login(ctx, pool_id, client_id, doomed_user, password)
    ok_token = _create_confirmed_user_and_login(ctx, pool_id, client_id, ok_user, password)

    cip.admin_delete_user(UserPoolId=pool_id, Username=doomed_user)

    code, message = _error(lambda: cip.get_user_auth_factors(AccessToken=doomed_token))
    assert code == "UserNotFoundException", f"expected UserNotFoundException, got {code}"
    expected = "User does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the deleted user's record is confirmed gone from the pool
    admin_code, admin_message = _error(lambda: cip.admin_get_user(UserPoolId=pool_id, Username=doomed_user))
    assert admin_code == "UserNotFoundException", f"expected UserNotFoundException, got {admin_code}"
    expected_admin = "User does not exist."
    assert admin_message == expected_admin, f"expected message {expected_admin!r}, got {admin_message!r}"

    # positive control: an un-deleted user's token in the same pool still resolves
    factors = cip.get_user_auth_factors(AccessToken=ok_token)
    assert factors["Username"] == ok_user, f"expected {ok_user!r}, got {factors.get('Username')!r}"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because a
    target that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx):
    cip = ctx.client("cognito-idp")
    pool_id = cip.create_user_pool(
        PoolName=ctx.unique_name("sim2real-cog-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cip.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id):
    cip = ctx.client("cognito-idp")
    return cip.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-cog-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]


def _create_confirmed_user_and_login(ctx, pool_id, client_id, username, password, extra_attrs=None):
    cip = ctx.client("cognito-idp")
    cip.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=extra_attrs or [],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cip.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    resp = cip.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
