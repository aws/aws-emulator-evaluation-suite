"""revoke-token-access-token-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-token-access-token-type-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeToken with an access token fails with UnsupportedTokenTypeException and its exact message,
    while revoking the matching refresh token succeeds and REFRESH_TOKEN_AUTH with it then fails with
    NotAuthorizedException and its exact message."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], DeletionProtection="INACTIVE", UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False, EnableTokenRevocation=True)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]
    refresh_token = auth["RefreshToken"]

    code, message = _rejection(lambda: c.revoke_token(Token=access_token, ClientId=client_id))
    assert code == "UnsupportedTokenTypeException", (
        f"expected UnsupportedTokenTypeException, got {code}"
    )
    assert message == "Unsupported token type", f"expected message 'Unsupported token type', got {message!r}"

    # Positive control: RevokeToken itself works on this account/credentials --
    # the matching REFRESH token is revoked without error.
    c.revoke_token(Token=refresh_token, ClientId=client_id)

    # Independent read at the destination, through a different operation than the
    # one that mutated: the revoked refresh token can no longer mint new tokens.
    effect_code, effect_message = _rejection(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
    )
    assert effect_code == "NotAuthorizedException", (
        f"expected the revoked refresh token to be rejected by REFRESH_TOKEN_AUTH, got {effect_code}"
    )
    expected_message = "Refresh Token has been revoked"
    assert effect_message == expected_message, f"expected message {expected_message!r}, got {effect_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
