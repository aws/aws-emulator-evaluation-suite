"""op-contract-revoke-token."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-revoke-token"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeToken invalidates the refresh token for future use; passing a non-refresh token is rejected."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = _password()
    _create_confirmed_user(ctx, pool_id, username, password)

    auth = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    refresh_token = auth["AuthenticationResult"]["RefreshToken"]

    # refresh token works before revocation
    idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )

    idp.revoke_token(Token=refresh_token, ClientId=client_id)

    code, message = _error(
        lambda: idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
    )
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException for a revoked refresh token, got {code}"
    expected = "Refresh Token has been revoked"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    boundary_code, boundary_message = _error(lambda: idp.revoke_token(Token=access_token, ClientId=client_id))
    assert boundary_code == "UnsupportedTokenTypeException", (
        f"expected UnsupportedTokenTypeException revoking an access token, got {boundary_code}"
    )
    expected = "Unsupported token type"
    assert boundary_message == expected, f"expected message {expected!r}, got {boundary_message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _password() -> str:
    return "Sim2Real!23Aa"


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "UserPoolId": pool_id,
        "ClientName": ctx.unique_name("sim2real-behav-client-"),
        "ExplicitAuthFlows": [
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_SRP_AUTH",
        ],
        "EnableTokenRevocation": True,
    }
    params.update(overrides)
    resp = idp.create_user_pool_client(**params)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
