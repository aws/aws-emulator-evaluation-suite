"""deep-cognito-idp-2-token-rotation-grace-replay-supersedes-rotated-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-grace-replay-supersedes-rotated-token"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
REPLAY_DEADLINE_S = 40.0  # well inside the 60 s grace window


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A grace-period replay of a rotated-out token mints a token that supersedes the first
    rotation's output: that never-redeemed token is then refused as RefreshTokenReuseException.
    """
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rot-g60-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 60},
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

    t_rotated = time.monotonic()
    rt1 = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0)["AuthenticationResult"]["RefreshToken"]
    assert rt1 != rt0, "rotation returned the same refresh token it was given"

    elapsed = time.monotonic() - t_rotated
    # elapsed-bound: the replay must fall inside the 60 s RetryGracePeriodSeconds window it tests.
    assert elapsed < REPLAY_DEADLINE_S, (
        f"precondition: replay not issued inside the grace window ({elapsed:.1f}s after rotation)"
    )
    replay = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt0)["AuthenticationResult"]
    rtx = replay.get("RefreshToken")
    assert rtx and rtx not in (rt0, rt1), "grace replay did not mint a distinct refresh token"

    # The negative: the first rotation's output, never presented until now, has been superseded.
    code, message = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt1))
    assert code == "RefreshTokenReuseException", (
        f"the superseded rotated-in token returned {code!r} ({message!r}), expected RefreshTokenReuseException"
    )
    expected_message = "Refresh token reuse detected"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Positive control: the newest token in the family is live and its tokens are usable.
    latest = c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rtx)["AuthenticationResult"]
    assert latest.get("RefreshToken") and latest["RefreshToken"] not in (rt0, rt1, rtx), (
        "redeeming the newest token did not rotate it"
    )
    whoami = c.get_user(AccessToken=latest["AccessToken"])
    assert whoami["Username"] == username, f"newest-token access token resolved to {whoami['Username']!r}"

    # And the refusal of rt1 was terminal, not a transient: it is still refused.
    code_again, message_again = _error(lambda: c.get_tokens_from_refresh_token(ClientId=client_id, RefreshToken=rt1))
    assert code_again == "RefreshTokenReuseException", (
        f"superseded token on second presentation returned {code_again!r} ({message_again!r})"
    )
    expected_message_again = "Refresh token reuse detected"
    assert message_again == expected_message_again, f"expected message {expected_message_again!r}, got {message_again!r}"


# ===== helpers =====

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
