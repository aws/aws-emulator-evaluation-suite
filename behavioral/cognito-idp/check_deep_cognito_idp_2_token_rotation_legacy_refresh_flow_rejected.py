"""deep-cognito-idp-2-token-rotation-legacy-refresh-flow-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-legacy-refresh-flow-rejected"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A refresh token from a rotating client is refused on InitiateAuth REFRESH_TOKEN_AUTH with
    UnsupportedOperationException and the exact message, and is not spent: GetTokensFromRefreshToken
    then redeems it for a new refresh token that works."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rot-g0-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0},
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-rot-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    rt0 = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["RefreshToken"]

    code, message = _error(lambda: c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH", AuthParameters={"REFRESH_TOKEN": rt0},
    ))
    assert code == "UnsupportedOperationException", (
        f"REFRESH_TOKEN_AUTH on a rotating client returned {code!r} ({message!r}), "
        "expected UnsupportedOperationException"
    )
    expected_message = "This API does not support refresh token rotation"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control + effect absent: the refused attempt did not spend the token.
    redeemed = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0)["AuthenticationResult"]
    assert redeemed.get("RefreshToken") and redeemed["RefreshToken"] != rt0, (
        f"GetTokensFromRefreshToken after the refused legacy attempt did not rotate; keys {sorted(redeemed)!r}"
    )
    whoami = c.get_user(AccessToken=redeemed["AccessToken"])
    assert whoami["Username"] == username, f"redeemed access token resolved to {whoami['Username']!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    keys = sorted((out or {}).get("AuthenticationResult", out or {}))
    raise AssertionError(f"call expected to fail SUCCEEDED (response keys {keys!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
