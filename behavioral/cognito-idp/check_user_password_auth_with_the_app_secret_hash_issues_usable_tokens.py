"""user-password-auth-with-the-app-secret-hash-issues-usable-tokens."""
from __future__ import annotations

import base64
import hashlib
import hmac

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-password-auth-with-the-app-secret-hash-issues-usable-tokens"
GROUP = 'confidential-app-client'
SERVICES = ['cognito-idp']

PASSWORD = "Sim2Real!Signin9"


def _auth_secret_hash(secret: str, username: str, client_id: str) -> str:
    """Base64 of HMAC-SHA256 over ``username + client_id`` keyed by the app client's secret."""
    mac = hmac.new(secret.encode("utf-8"), f"{username}{client_id}".encode("utf-8"), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def _denial(call):
    """``(Code, Message)`` of the ClientError ``call()`` raises; an accepted call is a failure."""
    try:
        answer = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"a denial was required but the call was accepted: {answer!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """USER_PASSWORD_AUTH on an app client with a secret is denied without a SECRET_HASH auth
    parameter and, with the recomputed one, returns an access token that GetUser accepts and that
    resolves to the same identity AdminGetUser stores."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cipauth-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _pool=pool_id: cognito.delete_user_pool(UserPoolId=_pool))

    confidential = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cipauth-client-"),
        GenerateSecret=True,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]
    client_id = confidential["ClientId"]
    ctx.on_cleanup(
        lambda _pool=pool_id, _client=client_id: cognito.delete_user_pool_client(
            UserPoolId=_pool, ClientId=_client
        )
    )
    secret = confidential["ClientSecret"]

    username = ctx.unique_name("sim2real-behav-cipauth-user-")
    cognito.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _pool=pool_id, _user=username: cognito.admin_delete_user(
            UserPoolId=_pool, Username=_user
        )
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )

    # The legal neighbour of the signed-in request below: everything but the auth parameter.
    denied_code, denied_message = _denial(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    assert denied_code == "NotAuthorizedException", (
        f"expected the hashless sign-in to be denied, got {denied_code}: {denied_message!r}"
    )
    assert denied_message == (
        f"Client {client_id} is configured with secret but SECRET_HASH was not received"
    ), f"unexpected denial message for the hashless sign-in: {denied_message!r}"

    signed_in = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": PASSWORD,
            "SECRET_HASH": _auth_secret_hash(secret, username, client_id),
        },
    )
    assert "ChallengeName" not in signed_in, (
        f"a permanent password should sign the user straight in, got {signed_in.get('ChallengeName')!r}"
    )
    tokens = signed_in["AuthenticationResult"]
    assert tokens["TokenType"] == "Bearer", (
        f"expected a Bearer token type, got {tokens['TokenType']!r}"
    )

    # The token is only usable if the service really minted it for this user.
    whoami = cognito.get_user(AccessToken=tokens["AccessToken"])
    assert whoami["Username"] == username, (
        f"the access token should resolve the signed-in username, got {whoami['Username']!r}"
    )
    token_sub = {a["Name"]: a["Value"] for a in whoami["UserAttributes"]}["sub"]

    stored = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    stored_sub = {a["Name"]: a["Value"] for a in stored["UserAttributes"]}["sub"]
    assert token_sub == stored_sub, (
        "the identity behind the access token must be the one the pool stores, and the two differ"
    )
    assert stored["UserStatus"] == "CONFIRMED", (
        f"a permanent password should leave the user CONFIRMED, got {stored['UserStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
