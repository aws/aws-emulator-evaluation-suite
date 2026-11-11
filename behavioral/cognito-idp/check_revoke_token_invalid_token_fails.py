"""revoke-token-invalid-token-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-token-invalid-token-fails"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeToken on an unrecognized refresh token succeeds as a no-op (RFC 7009), and revoking a real
    refresh token makes GetTokensFromRefreshToken fail with NotAuthorizedException and its exact message."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    _admin_create_confirmed_user(ctx, pool_id, username, _PASSWORD)
    auth = _admin_login(ctx, pool_id, client_id, username, _PASSWORD)
    refresh_token = auth["RefreshToken"]

    # An unrecognized token is a no-op success: a ClientError here propagates and fails the check.
    cognito.revoke_token(Token="not-a-real-refresh-token.abc123", ClientId=client_id)

    # positive control: revoking the real refresh token succeeds
    cognito.revoke_token(Token=refresh_token, ClientId=client_id)

    # observe the effect: the revoked refresh token can no longer mint new tokens
    effect_code, effect_message = _rejection(
        lambda: cognito.get_tokens_from_refresh_token(RefreshToken=refresh_token, ClientId=client_id)
    )
    assert effect_code == "NotAuthorizedException", (
        f"expected NotAuthorizedException after revocation, got {effect_code}"
    )
    expected_message = "Refresh Token has been revoked"
    assert effect_message == expected_message, f"expected message {expected_message!r}, got {effect_message!r}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
        DeletionProtection="INACTIVE",
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        EnableTokenRevocation=True,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _admin_create_confirmed_user(ctx, pool_id, username, password, email=None, email_verified=False):
    cognito = ctx.client("cognito-idp")
    attrs = []
    if email:
        attrs.append({"Name": "email", "Value": email})
        if email_verified:
            attrs.append({"Name": "email_verified", "Value": "true"})
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=attrs,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_login(ctx, pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
