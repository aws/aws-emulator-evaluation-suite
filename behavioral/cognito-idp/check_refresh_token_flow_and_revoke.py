"""refresh-token-flow-and-revoke."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "refresh-token-flow-and-revoke"
GROUP = 'state-machine'
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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTokensFromRefreshToken issues a usable new AccessToken; RevokeToken
    on the refresh token then permanently invalidates it for further
    refreshes."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
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
    refresh_token = auth["RefreshToken"]

    refreshed = c.get_tokens_from_refresh_token(RefreshToken=refresh_token, ClientId=client_id)[
        "AuthenticationResult"
    ]
    new_access_token = refreshed["AccessToken"]
    assert new_access_token, "expected GetTokensFromRefreshToken to return a non-empty AccessToken"

    got = c.get_user(AccessToken=new_access_token)
    assert got["Username"] == username, got["Username"]

    c.revoke_token(Token=refresh_token, ClientId=client_id)

    code, message = _rejection(
        lambda: c.get_tokens_from_refresh_token(RefreshToken=refresh_token, ClientId=client_id)
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException refreshing a revoked token, got {code}"
    )
    expected_message = "Refresh Token has been revoked"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
