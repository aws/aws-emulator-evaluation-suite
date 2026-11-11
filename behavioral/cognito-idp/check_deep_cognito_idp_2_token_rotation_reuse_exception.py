"""deep-cognito-idp-2-token-rotation-reuse-exception."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-reuse-exception"
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
    """With refresh-token rotation enabled and a 0 s grace period, a rotated-out refresh token is
    refused with RefreshTokenReuseException and the exact message, while its successor rotates once
    and is then refused the same way."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rot-g0-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0},
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    assert client.get("RefreshTokenRotation") == {"Feature": "ENABLED", "RetryGracePeriodSeconds": 0}, (
        f"client echoed RefreshTokenRotation={client.get('RefreshTokenRotation')!r}"
    )

    username = ctx.unique_name("sim2real-behav-rot-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    signin = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    rt0 = signin["RefreshToken"]

    # Rotation: the first redemption succeeds and hands back a NEW refresh token.
    first = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0)["AuthenticationResult"]
    assert {"AccessToken", "IdToken", "RefreshToken"} <= set(first), (
        f"a rotating client must return access, id AND refresh tokens; got keys {sorted(first)!r}"
    )
    rt1 = first["RefreshToken"]
    assert rt1 != rt0, "rotation returned the same refresh token it was given"

    # The negative: replaying the spent token is reuse, with no grace period to absorb it.
    code, message = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0))
    assert code == "RefreshTokenReuseException", (
        f"replaying a rotated-out refresh token returned {code!r} ({message!r}), "
        "expected RefreshTokenReuseException"
    )
    expected_message = "Refresh token reuse detected"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control in the same family: the rotated-in token is live and yields usable tokens.
    second = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt1)["AuthenticationResult"]
    rt2 = second.get("RefreshToken")
    assert rt2 and rt2 not in (rt0, rt1), "redeeming the rotated-in token did not rotate it to a fresh token"
    whoami = c.get_user(AccessToken=second["AccessToken"])
    assert whoami["Username"] == username, (
        f"access token from the rotated-in refresh token resolved to {whoami['Username']!r}, expected {username!r}"
    )

    # Each rotation spends its input: rt1 is now dead too, and rt0 stays dead.
    code1, message1 = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt1))
    assert code1 == "RefreshTokenReuseException", (
        f"replaying the second-generation token after its rotation returned {code1!r} ({message1!r})"
    )
    expected_message1 = "Refresh token reuse detected"
    assert message1 == expected_message1, f"expected message {expected_message1!r}, got {message1!r}"
    code0, message0 = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0))
    assert code0 == "RefreshTokenReuseException", (
        f"the original token came back to life after a later rotation: {code0!r} ({message0!r})"
    )
    expected_message0 = "Refresh token reuse detected"
    assert message0 == expected_message0, f"expected message {expected_message0!r}, got {message0!r}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises. An unexpected success is itself the
    finding, so it raises rather than returning a sentinel that reads like a code."""
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
