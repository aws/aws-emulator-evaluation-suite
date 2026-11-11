"""global-sign-out-revokes-every-session-and-refresh-token-but-a-later-sign-in-works."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "global-sign-out-revokes-every-session-and-refresh-token-but-a-later-sign-in-works"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real-Behav-Pass-1!"
NEW_PASSWORD = "Sim2Real-Behav-Pass-2!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_REVOKED_ACCESS = ("NotAuthorizedException", "Access Token has been revoked")
_REVOKED_REFRESH = ("NotAuthorizedException", "Refresh Token has been revoked")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GlobalSignOut with one access token revokes the access and refresh tokens of every session of
    the user on every app client; the revoked token is then refused by GlobalSignOut and
    ChangePassword, and a sign-in made after the sign-out works."""
    c = ctx.client("cognito-idp")
    pool_id = _pool(ctx, c)
    client_x = _client(ctx, c, pool_id)
    client_y = _client(ctx, c, pool_id)
    username = _user(ctx, c, pool_id)
    sessions = [
        (client_x, _sign_in(c, pool_id, client_x, username)),
        (client_x, _sign_in(c, pool_id, client_x, username)),
        (client_y, _sign_in(c, pool_id, client_y, username)),
    ]
    access_tokens = []
    for client_id, tokens in sessions:
        refreshed = _refresh(c, client_id, tokens)["AccessToken"]
        access_tokens += [tokens["AccessToken"], refreshed]
    for n, token in enumerate(access_tokens, 1):
        assert c.get_user(AccessToken=token)["Username"] == username, f"access token {n}: GetUser failed before the sign-out"

    caller = sessions[0][1]["AccessToken"]
    out = c.global_sign_out(AccessToken=caller)
    body = {k: v for k, v in out.items() if k != "ResponseMetadata"}
    assert body == {}, f"GlobalSignOut returned keys {sorted(body)!r}, expected an empty body"

    for token in access_tokens:
        expect_error(lambda t=token: c.get_user(AccessToken=t), *_REVOKED_ACCESS)
    for client_id, tokens in sessions:
        expect_error(lambda i=client_id, t=tokens: _refresh(c, i, t), *_REVOKED_REFRESH)

    expect_error(lambda: c.global_sign_out(AccessToken=caller), *_REVOKED_ACCESS)
    expect_error(lambda: c.change_password(AccessToken=caller, PreviousPassword=PASSWORD, ProposedPassword=NEW_PASSWORD),
                 *_REVOKED_ACCESS)

    fresh = _sign_in_after_revocation(c, pool_id, client_x, username)
    refreshed = _refresh(c, client_x, fresh)["AccessToken"]
    me = c.get_user(AccessToken=refreshed)
    assert me["Username"] == username, f"the post-sign-out refreshed access token resolved to {me.get('Username')!r}"


def _sign_in_after_revocation(c, pool_id, client_id, username, budget_s=10.0):
    """Sign in until GetUser accepts the new access token: the revocation cutoff is whole-second."""
    deadline = time.monotonic() + budget_s
    while True:
        tokens = _sign_in(c, pool_id, client_id, username)
        try:
            me = c.get_user(AccessToken=tokens["AccessToken"])
        except ClientError as exc:
            got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
            if got != _REVOKED_ACCESS or time.monotonic() > deadline:
                raise
            time.sleep(0.5)
            continue
        assert me["Username"] == username, f"the post-sign-out access token resolved to {me.get('Username')!r}"
        return tokens


def _sign_in(c, pool_id, client_id, username):
    return c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]


def _refresh(c, client_id, tokens):
    return c.initiate_auth(
        ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": tokens["RefreshToken"]},
    )["AuthenticationResult"]


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: keys {sorted(result)!r}")


def _pool(ctx, c):
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _client(ctx, c, pool_id):
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False, ExplicitAuthFlows=AUTH_FLOWS,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _user(ctx, c, pool_id):
    username = ctx.unique_name("sim2real-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)
    return username


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
