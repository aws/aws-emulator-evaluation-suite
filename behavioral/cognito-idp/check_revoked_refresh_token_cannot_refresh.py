"""revoked-refresh-token-cannot-refresh."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoked-refresh-token-cannot-refresh"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """After RevokeToken invalidates a refresh token, GetTokensFromRefreshToken using
    that same token must be rejected rather than issuing fresh tokens."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username, password = _create_confirmed_user(ctx, pool_id)

    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    refresh_token = auth["AuthenticationResult"]["RefreshToken"]

    # Sanity: the refresh token works before revocation.
    fresh = idp.get_tokens_from_refresh_token(RefreshToken=refresh_token, ClientId=client_id)
    assert "AccessToken" in fresh["AuthenticationResult"], (
        f"expected an AccessToken from a live refresh token, got keys "
        f"{sorted(fresh['AuthenticationResult'].keys())!r}"
    )

    idp.revoke_token(Token=refresh_token, ClientId=client_id)

    code, message = _rejection(lambda: idp.get_tokens_from_refresh_token(
        RefreshToken=refresh_token, ClientId=client_id
    ))
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a revoked refresh token, got {code!r}"
    )
    expected_message = "Refresh Token has been revoked"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _create_pool_and_client(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))
    return pool_id, client_id


def _create_confirmed_user(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username,
        TemporaryPassword="Temp0rary!Passw0rd", MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
