"""change-password-validates-previous-before-policy-and-leaves-every-other-session-signed-in."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-password-validates-previous-before-policy-and-leaves-every-other-session-signed-in"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real-Behav-Pass-1!"
NEW_PASSWORD = "Sim2Real-Behav-Pass-2!"
WRONG_PASSWORD = "Sim2Real-Behav-Pass-9!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
_BAD_CREDENTIALS = ("NotAuthorizedException", "Incorrect username or password.")
_WEAK_PROPOSED = ("InvalidPasswordException", "Password did not conform with policy: Password not long enough")
_NO_PREVIOUS = ("InvalidParameterException", "Missing required parameter OldPassword")
_BAD_TOKEN = ("NotAuthorizedException", "Invalid Access Token")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ChangePassword checks the previous password before the policy and refuses an omitted
    PreviousPassword or a malformed token; a successful change, to the same or a new password,
    revokes nothing, so every other session's access and refresh tokens keep working."""
    c = ctx.client("cognito-idp")
    pool_id = _pool(ctx, c)
    client_x = _client(ctx, c, pool_id)
    client_y = _client(ctx, c, pool_id)
    username = _user(ctx, c, pool_id)
    s1 = _sign_in(c, pool_id, client_x, username, PASSWORD)["AuthenticationResult"]
    s2 = _sign_in(c, pool_id, client_y, username, PASSWORD)["AuthenticationResult"]
    token = s1["AccessToken"]

    expect_error(lambda: c.change_password(AccessToken=token, PreviousPassword=WRONG_PASSWORD, ProposedPassword="Ab1"),
                 *_BAD_CREDENTIALS)
    expect_error(lambda: c.change_password(AccessToken=token, PreviousPassword=PASSWORD, ProposedPassword="Ab1!"),
                 *_WEAK_PROPOSED)
    expect_error(lambda: c.change_password(AccessToken=token, ProposedPassword=NEW_PASSWORD), *_NO_PREVIOUS)
    expect_error(lambda: c.change_password(AccessToken="not-a-token", PreviousPassword=PASSWORD,
                                           ProposedPassword=NEW_PASSWORD), *_BAD_TOKEN)
    _assert_signs_in(c, pool_id, client_x, username, PASSWORD)

    c.change_password(AccessToken=token, PreviousPassword=PASSWORD, ProposedPassword=PASSWORD)
    _assert_signs_in(c, pool_id, client_x, username, PASSWORD)

    c.change_password(AccessToken=token, PreviousPassword=PASSWORD, ProposedPassword=NEW_PASSWORD)
    expect_error(lambda: _sign_in(c, pool_id, client_x, username, PASSWORD), *_BAD_CREDENTIALS)
    _assert_signs_in(c, pool_id, client_x, username, NEW_PASSWORD)

    for label, client_id, session in (("caller", client_x, s1), ("other client", client_y, s2)):
        me = c.get_user(AccessToken=session["AccessToken"])
        assert me["Username"] == username, f"{label} access token after the change resolved to {me.get('Username')!r}"
        refreshed = c.initiate_auth(
            ClientId=client_id, AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": session["RefreshToken"]},
        )["AuthenticationResult"]
        me = c.get_user(AccessToken=refreshed["AccessToken"])
        assert me["Username"] == username, f"{label} refreshed access token resolved to {me.get('Username')!r}"


def _assert_signs_in(c, pool_id, client_id, username, password):
    tokens = _sign_in(c, pool_id, client_id, username, password)["AuthenticationResult"]
    me = c.get_user(AccessToken=tokens["AccessToken"])
    assert me["Username"] == username, f"the signed-in access token resolved to {me.get('Username')!r}"


def _sign_in(c, pool_id, client_id, username, password):
    return c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )


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
