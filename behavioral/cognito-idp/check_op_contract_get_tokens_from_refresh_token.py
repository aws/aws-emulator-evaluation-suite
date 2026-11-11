"""op-contract-get-tokens-from-refresh-token."""
from __future__ import annotations

import base64
import json

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-get-tokens-from-refresh-token"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetTokensFromRefreshToken exchanges a real refresh token (obtained from a live
    sign-in) for a fresh access/ID token pair, and rejects a garbage refresh token with
    NotAuthorizedException instead of issuing tokens for it."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
        TemporaryPassword="Sim2Real-Temp-1!",
    )
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password="Sim2Real-Real-1!", Permanent=True)

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": "Sim2Real-Real-1!"},
    )
    original = auth["AuthenticationResult"]
    refresh_token = original["RefreshToken"]

    # success path: the refresh token yields a fresh access/ID token pair
    refreshed = idp.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=refresh_token)
    result = refreshed["AuthenticationResult"]
    assert result["AccessToken"], "expected a non-empty AccessToken"
    assert result["IdToken"], "expected a non-empty IdToken"
    assert result["AccessToken"] != original["AccessToken"], "expected a freshly issued access token"
    assert not result.get("RefreshToken"), (
        f"GetTokensFromRefreshToken must not reissue a RefreshToken by default, got {result.get('RefreshToken')!r}"
    )

    claims = _decode_jwt_segment(result["AccessToken"].split(".")[1])
    assert claims.get("client_id") == client_id, (
        f"expected client_id {client_id!r} in the refreshed AccessToken, got {claims.get('client_id')!r}"
    )

    # independent read at the destination, through a different operation: the
    # refreshed AccessToken must actually authenticate, not merely look non-empty
    whoami = idp.get_user(AccessToken=result["AccessToken"])
    assert whoami["Username"] == username, (
        f"expected get_user with the refreshed AccessToken to resolve to {username!r}, got {whoami.get('Username')!r}"
    )

    # distinct error boundary: a garbage refresh token is rejected, not exchanged
    code, message = _error(lambda: idp.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken="not-a-real-refresh-token"))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code!r}"
    expected = "Invalid Refresh Token"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _decode_jwt_segment(segment: str) -> dict:
    padding = "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(segment + padding))


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
