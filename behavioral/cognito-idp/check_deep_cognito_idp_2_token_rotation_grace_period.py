"""deep-cognito-idp-2-token-rotation-grace-period."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-grace-period"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
TOKEN_VALIDITY_MIN = 20  # deliberately not the 60 min default, so a hardcoded default cannot pass
# The replay must land well inside the 60 s window; fail loudly rather than grade a replay
# that may have fallen outside it.
REPLAY_DEADLINE_S = 40.0


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """Replaying a rotated-out refresh token is refused on a 0 s grace client and honoured on a
    60 s twin, and the grace reissue is a fresh token set with the rotation's validity window.
    """
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    clients = {}
    for grace in (0, 60):
        cl = c.create_user_pool_client(
            UserPoolId=pool_id,
            ClientName=ctx.unique_name(f"sim2real-behav-rot-g{grace}-"),
            ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
            RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": grace},
            AccessTokenValidity=TOKEN_VALIDITY_MIN,
            IdTokenValidity=TOKEN_VALIDITY_MIN,
            TokenValidityUnits={"AccessToken": "minutes", "IdToken": "minutes"},
        )["UserPoolClient"]
        cid = cl["ClientId"]
        ctx.on_cleanup(lambda _c=cid: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=_c))
        assert cl.get("RefreshTokenRotation") == {"Feature": "ENABLED", "RetryGracePeriodSeconds": grace}, (
            f"client echoed RefreshTokenRotation={cl.get('RefreshTokenRotation')!r} for grace {grace}"
        )
        clients[grace] = cid

    username = ctx.unique_name("sim2real-behav-rot-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    expected_window = TOKEN_VALIDITY_MIN * 60

    # --- 60 s client: rotate, then replay the spent token inside the grace window.
    rt0 = _sign_in(c, clients[60], username)
    t_rotated = time.monotonic()
    rotated = c.get_tokens_from_refresh_token(ClientId=clients[60], RefreshToken=rt0)["AuthenticationResult"]
    rt1 = rotated["RefreshToken"]
    assert rt1 != rt0, "rotation returned the same refresh token it was given"
    rot_at, rot_id = _claims(rotated["AccessToken"]), _claims(rotated["IdToken"])
    for label, cl in (("access", rot_at), ("id", rot_id)):
        assert cl["exp"] - cl["iat"] == expected_window, (
            f"rotation's {label} token window is {cl['exp'] - cl['iat']!r}s, expected {expected_window}s"
        )
    assert rotated["ExpiresIn"] == expected_window, f"rotation ExpiresIn={rotated['ExpiresIn']!r}"

    elapsed = time.monotonic() - t_rotated
    # elapsed-bound: the replay must fall inside the 60 s RetryGracePeriodSeconds window it tests.
    assert elapsed < REPLAY_DEADLINE_S, (
        f"precondition: replay not issued inside the grace window ({elapsed:.1f}s after rotation)"
    )
    replay = c.get_tokens_from_refresh_token(ClientId=clients[60], RefreshToken=rt0)["AuthenticationResult"]
    assert {"AccessToken", "IdToken", "RefreshToken"} <= set(replay), (
        f"grace-period replay must return a full token set; got keys {sorted(replay)!r}"
    )
    assert replay["RefreshToken"] not in (rt0, rt1), (
        "grace-period replay echoed an existing refresh token instead of issuing a new one"
    )
    rep_at, rep_id = _claims(replay["AccessToken"]), _claims(replay["IdToken"])
    for label, rot, rep in (("access", rot_at, rep_at), ("id", rot_id, rep_id)):
        assert rep["exp"] - rep["iat"] == rot["exp"] - rot["iat"], (
            f"grace replay {label} token window {rep['exp'] - rep['iat']!r}s differs from the "
            f"rotation's {rot['exp'] - rot['iat']!r}s"
        )
        assert rep["iat"] >= rot["iat"], (
            f"grace replay {label} token iat {rep['iat']!r} predates the rotation's {rot['iat']!r}"
        )
    assert replay["ExpiresIn"] == rotated["ExpiresIn"], (
        f"grace replay ExpiresIn={replay['ExpiresIn']!r}, rotation set {rotated['ExpiresIn']!r}"
    )
    assert rep_at.get("client_id") == clients[60], f"replayed access token client_id={rep_at.get('client_id')!r}"
    whoami = c.get_user(AccessToken=replay["AccessToken"])
    assert whoami["Username"] == username, f"grace-replay access token resolved to {whoami['Username']!r}"

    # --- 0 s twin: the identical sequence is refused as reuse.
    tw0 = _sign_in(c, clients[0], username)
    twin_rot = c.get_tokens_from_refresh_token(ClientId=clients[0], RefreshToken=tw0)["AuthenticationResult"]
    assert twin_rot.get("RefreshToken") and twin_rot["RefreshToken"] != tw0, "0 s twin did not rotate"
    code, message = _error(lambda: c.get_tokens_from_refresh_token(ClientId=clients[0], RefreshToken=tw0))
    assert code == "RefreshTokenReuseException", (
        f"the same replay on the 0 s twin returned {code!r} ({message!r}), expected RefreshTokenReuseException"
    )
    expected_message = "Refresh token reuse detected"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====

def _sign_in(c, client_id: str, username: str) -> str:
    return c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["RefreshToken"]


def _claims(jwt: str) -> dict:
    seg = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


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
