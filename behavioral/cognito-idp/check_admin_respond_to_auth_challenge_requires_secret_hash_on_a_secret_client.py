"""admin-respond-to-auth-challenge-requires-secret-hash-on-a-secret-client."""
from __future__ import annotations

import base64
import hashlib
import hmac

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-respond-to-auth-challenge-requires-secret-hash-on-a-secret-client"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

TEMP_PASSWORD = "Sim2Real-Behav-Temp-1!"
NEW_PASSWORD = "Sim2Real-Behav-Pass-2!"
AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """On an app client with a secret, AdminRespondToAuthChallenge refuses a response with no
    SECRET_HASH or a wrong one without applying it, and the right hash then completes the same session."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=True, ExplicitAuthFlows=AUTH_FLOWS,
    )["UserPoolClient"]
    client_id, secret = client["ClientId"], client["ClientSecret"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    username = ctx.unique_name("sim2real-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword=TEMP_PASSWORD,
                        MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    right_hash = _secret_hash(username, client_id, secret)

    started = c.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": TEMP_PASSWORD, "SECRET_HASH": right_hash},
    )
    assert started.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", f"unexpected start: {started.get('ChallengeName')!r}"
    session = started["Session"]

    def respond(extra):
        return c.admin_respond_to_auth_challenge(
            UserPoolId=pool_id, ClientId=client_id, ChallengeName="NEW_PASSWORD_REQUIRED", Session=session,
            ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": NEW_PASSWORD, **extra},
        )

    no_hash = ("NotAuthorizedException", f"Client {client_id} is configured with secret but SECRET_HASH was not received")
    bad_hash = ("NotAuthorizedException", f"Unable to verify secret hash for client {client_id}")
    expect_error(lambda: respond({}), *no_hash)
    expect_error(lambda: respond({"SECRET_HASH": _secret_hash(username, client_id, "wrong" + secret)}), *bad_hash)
    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "FORCE_CHANGE_PASSWORD", f"a refused response changed the user to {status!r}"

    result = respond({"SECRET_HASH": right_hash})["AuthenticationResult"]
    assert result["TokenType"] == "Bearer", f"TokenType is {result['TokenType']!r}"
    me = c.get_user(AccessToken=result["AccessToken"])
    assert me["Username"] == username, f"the completed session's access token resolved to {me.get('Username')!r}"
    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"the completed challenge left the user {status!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
