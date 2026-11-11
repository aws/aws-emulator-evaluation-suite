"""secret-hash-required-for-confidential-client-auth."""
from __future__ import annotations

import base64
import hashlib
import hmac

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "secret-hash-required-for-confidential-client-auth"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"
AUTH_FLOWS = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _secret_hash(username: str, client_id: str, client_secret: str) -> str:
    """SECRET_HASH = base64(HMAC-SHA256(key=client_secret, msg=username + client_id))."""
    digest = hmac.new(
        client_secret.encode("utf-8"),
        (username + client_id).encode("utf-8"),
        hashlib.sha256,
    ).digest()
    return base64.b64encode(digest).decode("ascii")


def _rejection(fn) -> tuple:
    """Run fn and return the AWS (Error.Code, Error.Message) it raised. An unexpected SUCCESS
    raises, because a target that authenticates without (or with a wrong) SECRET_HASH is the
    security bypass this check exists to catch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(
        f"expected NotAuthorizedException, but the call SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A confidential client's InitiateAuth fails with NotAuthorizedException for a missing or wrong
    SECRET_HASH, as does AdminInitiateAuth without one, each with its exact message and no change to the
    user; the correct hash returns tokens on both, as the secret is what makes the client confidential."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    created = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(AUTH_FLOWS),
        GenerateSecret=True,
    )["UserPoolClient"]
    client_id = created["ClientId"]
    ctx.on_cleanup(
        lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
    )
    client_secret = created.get("ClientSecret")
    assert client_secret, (
        f"CreateUserPoolClient(GenerateSecret=True) must return a ClientSecret, got keys "
        f"{sorted(created)}"
    )

    username = ctx.unique_name("sim2real-behav-cipuser")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(
        lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
    )
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True
    )
    status_before = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_before == "CONFIRMED", (
        f"expected CONFIRMED after a permanent password set, got {status_before}"
    )

    good_hash = _secret_hash(username, client_id, client_secret)
    bad_hash = _secret_hash(username, client_id, client_secret + "-tampered")
    assert bad_hash != good_hash, "test setup error: the tampered SECRET_HASH collided"

    # --- break exactly one thing: the SECRET_HASH ---
    missing, missing_message = _rejection(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    assert missing == "NotAuthorizedException", (
        f"InitiateAuth against a confidential client with NO SECRET_HASH must fail with "
        f"NotAuthorizedException, got {missing}"
    )
    missing_expected = f"Client {client_id} is configured with secret but SECRET_HASH was not received"
    assert missing_message == missing_expected, (
        f"expected message {missing_expected!r}, got {missing_message!r}"
    )

    wrong, wrong_message = _rejection(
        lambda: c.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": PASSWORD,
                "SECRET_HASH": bad_hash,
            },
        )
    )
    assert wrong == "NotAuthorizedException", (
        f"InitiateAuth with an incorrect SECRET_HASH must fail with NotAuthorizedException, "
        f"got {wrong}"
    )
    wrong_expected = f"Unable to verify secret hash for client {client_id}"
    assert wrong_message == wrong_expected, f"expected message {wrong_expected!r}, got {wrong_message!r}"

    admin_missing, admin_missing_message = _rejection(
        lambda: c.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
        )
    )
    assert admin_missing == "NotAuthorizedException", (
        f"AdminInitiateAuth against a confidential client with NO SECRET_HASH must also fail "
        f"with NotAuthorizedException, got {admin_missing}"
    )
    assert admin_missing_message == missing_expected, (
        f"expected message {missing_expected!r}, got {admin_missing_message!r}"
    )

    # --- effect absent: the rejected attempts changed nothing about the user ---
    status_after = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_after == "CONFIRMED", (
        f"rejected SECRET_HASH attempts must leave UserStatus at CONFIRMED, got {status_after}"
    )

    # --- control: the correctly-computed SECRET_HASH authenticates on both surfaces ---
    resp = c.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": PASSWORD,
            "SECRET_HASH": good_hash,
        },
    )
    assert "ChallengeName" not in resp, (
        f"unexpected challenge {resp.get('ChallengeName')} for a CONFIRMED user with a "
        f"permanent password"
    )
    for field in ("AccessToken", "IdToken", "RefreshToken"):
        assert resp["AuthenticationResult"].get(field), (
            f"expected {field} once the correct SECRET_HASH is supplied"
        )

    admin_result = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={
            "USERNAME": username,
            "PASSWORD": PASSWORD,
            "SECRET_HASH": good_hash,
        },
    )["AuthenticationResult"]
    assert admin_result.get("AccessToken"), (
        "expected AdminInitiateAuth to issue an AccessToken with the correct SECRET_HASH"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
