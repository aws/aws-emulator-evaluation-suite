"""admin-user-global-sign-out-is-idempotent-and-refuses-a-later-self-sign-out-of-the-revoked-token."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-user-global-sign-out-is-idempotent-and-refuses-a-later-self-sign-out-of-the-revoked-token"
GROUP = "auth-state-machine"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real-Behav-Pass-1!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_REVOKED_ACCESS = ("NotAuthorizedException", "Access Token has been revoked")
_NO_USER = ("UserNotFoundException", "User does not exist.")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminUserGlobalSignOut succeeds twice in a row, a later self-service GlobalSignOut with an
    access token it revoked is refused, and a token minted afterwards signs out normally."""
    c = ctx.client("cognito-idp")
    pool_id = _pool(ctx, c)
    client_id = _client(ctx, c, pool_id)
    username = _user(ctx, c, pool_id)
    before = _sign_in(c, pool_id, client_id, username)["AccessToken"]
    assert c.get_user(AccessToken=before)["Username"] == username, "the access token failed before any sign-out"

    for attempt in (1, 2):
        out = c.admin_user_global_sign_out(UserPoolId=pool_id, Username=username)
        body = {k: v for k, v in out.items() if k != "ResponseMetadata"}
        assert body == {}, f"AdminUserGlobalSignOut call {attempt} returned {body!r}"

    expect_error(lambda: c.global_sign_out(AccessToken=before), *_REVOKED_ACCESS)

    fresh = _sign_in_after_revocation(c, pool_id, client_id, username)["AccessToken"]
    c.global_sign_out(AccessToken=fresh)
    expect_error(lambda: c.get_user(AccessToken=fresh), *_REVOKED_ACCESS)

    nobody = ctx.unique_name("sim2real-user-")
    expect_error(lambda: c.admin_user_global_sign_out(UserPoolId=pool_id, Username=nobody), *_NO_USER)


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
