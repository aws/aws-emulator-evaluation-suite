"""sign-up-without-a-secret-hash-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sign-up-without-a-secret-hash-rejected"
GROUP = 'confidential-app-client'
SERVICES = ['cognito-idp']

PASSWORD = "Sim2Real!Signup7"


def _client_secret_hash(secret: str, username: str, client_id: str) -> str:
    """Base64 of HMAC-SHA256 over ``username + client_id`` keyed by the app client's secret."""
    mac = hmac.new(secret.encode("utf-8"), f"{username}{client_id}".encode("utf-8"), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def _refusal(call):
    """``(Code, Message)`` of the ClientError ``call()`` raises; an accepted call is a failure."""
    try:
        answer = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"a refusal was required but the call was accepted: {answer!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On an app client that carries a secret, SignUp without a SecretHash is refused and registers
    nobody, while the identical request carrying the recomputed hash registers the user."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cipsh-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _pool=pool_id: cognito.delete_user_pool(UserPoolId=_pool))

    confidential = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cipsh-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]
    client_id = confidential["ClientId"]
    ctx.on_cleanup(
        lambda _pool=pool_id, _client=client_id: cognito.delete_user_pool_client(
            UserPoolId=_pool, ClientId=_client
        )
    )
    secret = confidential["ClientSecret"]
    assert secret, "GenerateSecret=True must mint a client secret for the confidential client"

    username = ctx.unique_name("sim2real-behav-cipsh-user-")

    code, message = _refusal(
        lambda: cognito.sign_up(ClientId=client_id, Username=username, Password=PASSWORD)
    )
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for the hashless SignUp, got {code}: {message!r}"
    )
    assert message == f"Client {client_id} is configured with secret but SECRET_HASH was not received", (
        f"unexpected refusal message for the hashless SignUp: {message!r}"
    )

    absent_code, absent_message = _refusal(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    )
    assert absent_code == "UserNotFoundException", (
        f"the refused SignUp must leave no user; AdminGetUser answered {absent_code}: {absent_message!r}"
    )

    # The refused input's legal neighbour: the same request plus the hash the client can recompute.
    registered = cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=PASSWORD,
        SecretHash=_client_secret_hash(secret, username, client_id),
    )
    ctx.on_cleanup(
        lambda _pool=pool_id, _user=username: cognito.admin_delete_user(
            UserPoolId=_pool, Username=_user
        )
    )
    assert registered["UserConfirmed"] is False, (
        f"a SignUp with no auto-confirmation must leave UserConfirmed false, got {registered!r}"
    )
    user_sub = registered["UserSub"]
    assert len(user_sub) == 36 and user_sub.count("-") == 4, (
        f"UserSub should be a UUID, got a value of length {len(user_sub)}"
    )

    stored = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert stored["UserStatus"] == "UNCONFIRMED", (
        f"expected the accepted SignUp to store an UNCONFIRMED user, got {stored['UserStatus']!r}"
    )
    attributes = {a["Name"]: a["Value"] for a in stored["UserAttributes"]}
    assert attributes["sub"] == user_sub, (
        "the stored sub must be the identifier SignUp returned, and the two do not match"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
