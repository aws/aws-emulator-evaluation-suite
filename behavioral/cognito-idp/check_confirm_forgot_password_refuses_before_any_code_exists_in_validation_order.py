"""confirm-forgot-password-refuses-before-any-code-exists-in-validation-order."""
from __future__ import annotations

import base64
import hashlib
import hmac

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-forgot-password-refuses-before-any-code-exists-in-validation-order"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

PASSWORD = "Sim2Real-Behav-Pass-1!"
NEW_PASSWORD = "Sim2Real-Behav-Pass-2!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
CODE = "123456"
_EXPIRED = ("ExpiredCodeException", "Invalid code provided, please request a code again.")
_NO_CHANNEL = ("InvalidParameterException",
               "Cannot reset password for the user as there is no registered/verified email or phone_number")
_NO_SUCH_USER = ("UserNotFoundException", "Username/client id combination not found.")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With no reset code outstanding, ConfirmForgotPassword checks the secret hash, then the user, then
    the code (ExpiredCode, ahead of the password policy); an unknown user is UserNotFound unless the
    client masks user existence, and ForgotPassword refuses a user with no verified channel."""
    c = ctx.client("cognito-idp")
    pool_id = _pool(ctx, c)
    plain = _client(ctx, c, pool_id, PreventUserExistenceErrors="LEGACY")
    masked = _client(ctx, c, pool_id, PreventUserExistenceErrors="ENABLED")
    secret_client = _client(ctx, c, pool_id, GenerateSecret=True)
    secret = c.describe_user_pool_client(UserPoolId=pool_id, ClientId=secret_client)["UserPoolClient"]["ClientSecret"]
    u1, u2, u3 = (_user(ctx, c, pool_id) for _ in range(3))

    expect_error(lambda: c.forgot_password(ClientId=plain, Username=u1), *_NO_CHANNEL)
    status = c.admin_get_user(UserPoolId=pool_id, Username=u1)["UserStatus"]
    assert status == "CONFIRMED", f"the refused reset left the user {status!r}"

    nobody = ctx.unique_name("sim2real-user-")
    no_hash = ("NotAuthorizedException", f"Client {secret_client} is configured with secret but SECRET_HASH was not received")
    bad_hash = ("NotAuthorizedException", f"Unable to verify secret hash for client {secret_client}")
    cases = [
        (_EXPIRED, plain, u1, NEW_PASSWORD, {}),
        (_EXPIRED, plain, u2, "Ab1", {}),
        (_NO_SUCH_USER, plain, nobody, "Ab1", {}),
        (_EXPIRED, masked, nobody, NEW_PASSWORD, {}),
        (no_hash, secret_client, u3, NEW_PASSWORD, {}),
        (bad_hash, secret_client, u3, NEW_PASSWORD, {"SecretHash": _secret_hash(u3, secret_client, "wrong" + secret)}),
        (_EXPIRED, secret_client, u3, NEW_PASSWORD, {"SecretHash": _secret_hash(u3, secret_client, secret)}),
    ]
    for pair, client_id, username, password, extra in cases:
        expect_error(lambda: c.confirm_forgot_password(
            ClientId=client_id, Username=username, ConfirmationCode=CODE, Password=password, **extra), *pair)

    for username in (u1, u2, u3):
        tokens = c.admin_initiate_auth(
            UserPoolId=pool_id, ClientId=plain, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )["AuthenticationResult"]
        me = c.get_user(AccessToken=tokens["AccessToken"])
        assert me["Username"] == username, f"{username}'s original password resolved to {me.get('Username')!r}"


def _secret_hash(username, client_id, client_secret):
    """SECRET_HASH = base64(HMAC-SHA256(key=client_secret, msg=username + client_id))."""
    digest = hmac.new(client_secret.encode(), (username + client_id).encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()


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


def _client(ctx, c, pool_id, **extra):
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=AUTH_FLOWS, **extra,
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
