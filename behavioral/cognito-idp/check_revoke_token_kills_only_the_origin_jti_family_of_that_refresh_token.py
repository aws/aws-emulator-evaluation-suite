"""revoke-token-kills-only-the-origin-jti-family-of-that-refresh-token."""
from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-token-kills-only-the-origin-jti-family-of-that-refresh-token"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"]
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
#: Revocation is a control-plane write read back on the token-authorization path, so it is
#: allowed a bounded settle window. The window is only meaningful because the twin session is
#: re-proved alive on every iteration inside it: a target that revokes everything fails
#: immediately rather than at the deadline.
_REVOKE_DEADLINE_S = 60.0


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """RevokeToken invalidates exactly the access tokens sharing the revoked refresh token's
    origin_jti, while a second concurrent session of the same user, its refresh token and the
    tokens it mints keep working."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=dict(_POOL_TAGS),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: c.delete_user_pool(UserPoolId=_p))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(FLOWS), GenerateSecret=False, EnableTokenRevocation=True,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    def _sign_in() -> dict:
        return c.initiate_auth(
            ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )["AuthenticationResult"]

    session_one = _sign_in()
    session_two = _sign_in()
    access_one, refresh_one = session_one["AccessToken"], session_one["RefreshToken"]
    access_two, refresh_two = session_two["AccessToken"], session_two["RefreshToken"]

    # --- positive control: BOTH sessions are usable in the same instant, before anything is
    # revoked. Without this leg, "the first token is refused" is indistinguishable from "this
    # pool never issued a usable token".
    for label, token in (("session-one", access_one), ("session-two", access_two)):
        who = c.get_user(AccessToken=token)
        assert who["Username"] == username, (
            f"{label}'s access token must identify {username} before any revocation, "
            f"GetUser returned {who.get('Username')!r}"
        )

    # --- the origin_jti family: each sign-in starts its own family, and a refresh keeps it ---
    claims_one = _claims(access_one)
    claims_two = _claims(access_two)
    for label, claims in (("session-one", claims_one), ("session-two", claims_two)):
        for claim in ("jti", "origin_jti"):
            assert claims.get(claim), (
                f"with EnableTokenRevocation=true the access token must carry a {claim} claim; "
                f"{label} claim keys were {sorted(claims)}"
            )
    assert claims_one["origin_jti"] != claims_two["origin_jti"], (
        f"two separate sign-ins must start two separate origin_jti families, both reported "
        f"{claims_one['origin_jti']!r}"
    )

    refreshed = c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_one},
    )["AuthenticationResult"]
    access_one_refreshed = refreshed["AccessToken"]
    claims_one_refreshed = _claims(access_one_refreshed)
    assert claims_one_refreshed.get("origin_jti") == claims_one["origin_jti"], (
        f"REFRESH_TOKEN_AUTH must preserve origin_jti; expected "
        f"{claims_one['origin_jti']!r}, got {claims_one_refreshed.get('origin_jti')!r}"
    )
    assert claims_one_refreshed.get("jti") != claims_one["jti"], (
        f"REFRESH_TOKEN_AUTH must mint a NEW jti; the refreshed token reused "
        f"{claims_one['jti']!r}"
    )
    who = c.get_user(AccessToken=access_one_refreshed)
    assert who["Username"] == username, (
        f"the refreshed access token must be usable before revocation, GetUser returned "
        f"{who.get('Username')!r}"
    )

    # --- break exactly one thing: revoke the FIRST refresh token only ---
    c.revoke_token(Token=refresh_one, ClientId=client_id)

    def _twin_still_alive() -> None:
        """The other session of the same user must survive the revocation, and is re-proved on
        every poll iteration so a target that kills everything fails immediately."""
        alive = c.get_user(AccessToken=access_two)
        assert alive["Username"] == username, (
            f"revoking session-one's refresh token must not disturb session-two; GetUser with "
            f"session-two's access token returned {alive.get('Username')!r}"
        )

    for label, token in (
        ("the access token from the revoked refresh token's auth event", access_one),
        ("the access token minted BY the revoked refresh token", access_one_refreshed),
    ):
        payload = _wait_until_rejected(
            lambda _t=token: c.get_user(AccessToken=_t), _twin_still_alive,
            description=f"GetUser refusing {label}",
        )
        code = payload["Error"]["Code"]
        assert code == "NotAuthorizedException", (
            f"expected NotAuthorizedException for {label} after RevokeToken, got {code!r} "
            f"(full payload {payload!r})"
        )
        message = payload["Error"].get("Message")
        assert message == "Access Token has been revoked", (
            f"expected message 'Access Token has been revoked' for {label}, got {message!r}"
        )

    revoked_refresh = _rejection_response(
        lambda: c.initiate_auth(
            ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_one},
        )
    )
    assert revoked_refresh["Error"]["Code"] == "NotAuthorizedException", (
        f"the revoked refresh token must not mint more tokens; expected "
        f"NotAuthorizedException, got {revoked_refresh['Error']['Code']!r}"
    )
    assert revoked_refresh["Error"].get("Message") == "Refresh Token has been revoked", (
        f"expected message 'Refresh Token has been revoked', got "
        f"{revoked_refresh['Error'].get('Message')!r}"
    )
    assert "AuthenticationResult" not in revoked_refresh, (
        f"tokens accompanied the refusal: {sorted(revoked_refresh)!r}"
    )

    # --- the untouched family is intact, read independently at the destination ---
    _twin_still_alive()
    survivor = c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_two},
    )["AuthenticationResult"]
    survivor_claims = _claims(survivor["AccessToken"])
    assert survivor_claims.get("origin_jti") == claims_two["origin_jti"], (
        f"the surviving refresh token must keep minting tokens in its own origin_jti family; "
        f"expected {claims_two['origin_jti']!r}, got {survivor_claims.get('origin_jti')!r}"
    )
    still_me = c.get_user(AccessToken=survivor["AccessToken"])
    assert still_me["Username"] == username, (
        f"a token minted by the untouched refresh token must be accepted by GetUser, got "
        f"{still_me.get('Username')!r}"
    )


# ===== helpers =====
def _claims(token: str) -> dict:
    """base64url-decode a JWT's payload segment."""
    parts = token.split(".")
    assert len(parts) == 3, f"not a well-formed JWT (header.payload.signature): {token[:24]!r}..."
    padded = parts[1] + "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: a target accepting
    what real AWS refuses is the strongest signal and must never be reported
    as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


def _wait_until_rejected(fn, invariant, *, description: str,
                         timeout_s: float = _REVOKE_DEADLINE_S, interval_s: float = 2.0) -> dict:
    """Poll fn() until it is REJECTED, re-asserting invariant() every iteration, and raise on
    timeout. The invariant is the twin control: it must keep holding for the whole window, so a
    target that revokes more than it was asked to fails on the first iteration instead of
    passing at the deadline."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        invariant()
        try:
            last = fn()
        except ClientError as e:
            return e.response
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} never happened within {timeout_s}s — the call still SUCCEEDED, which is "
        f"the over-permissive defect: {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
