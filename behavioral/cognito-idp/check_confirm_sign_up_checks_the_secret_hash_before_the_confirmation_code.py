"""confirm-sign-up-checks-the-secret-hash-before-the-confirmation-code."""
from __future__ import annotations

import base64
import hashlib
import hmac

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-sign-up-checks-the-secret-hash-before-the-confirmation-code"
GROUP = 'confidential-app-client'
SERVICES = ['cognito-idp']

PASSWORD = "Sim2Real!Confirm3"
NEVER_ISSUED_CODE = "246802"


def _app_secret_hash(secret: str, username: str, client_id: str) -> str:
    """Base64 of HMAC-SHA256 over ``username + client_id`` keyed by the app client's secret."""
    mac = hmac.new(secret.encode("utf-8"), f"{username}{client_id}".encode("utf-8"), hashlib.sha256)
    return base64.b64encode(mac.digest()).decode("ascii")


def _rejection(call):
    """``(Code, Message)`` of the ClientError ``call()`` raises; an accepted call is a failure."""
    try:
        answer = call()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"a rejection was required but the call was accepted: {answer!r}")


def _user_status(cognito, pool_id: str, username: str) -> str:
    return cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfirmSignUp on a confidential app client refuses a missing SecretHash before it looks at the
    confirmation code; the same request carrying the hash is refused by the code check instead, and
    neither refusal confirms a user that AdminConfirmSignUp then confirms."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cipcs-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _pool=pool_id: cognito.delete_user_pool(UserPoolId=_pool))

    confidential = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cipcs-client-"),
        GenerateSecret=True,
    )["UserPoolClient"]
    client_id = confidential["ClientId"]
    ctx.on_cleanup(
        lambda _pool=pool_id, _client=client_id: cognito.delete_user_pool_client(
            UserPoolId=_pool, ClientId=_client
        )
    )
    secret = confidential["ClientSecret"]

    username = ctx.unique_name("sim2real-behav-cipcs-user-")
    cognito.sign_up(
        ClientId=client_id,
        Username=username,
        Password=PASSWORD,
        SecretHash=_app_secret_hash(secret, username, client_id),
    )
    ctx.on_cleanup(
        lambda _pool=pool_id, _user=username: cognito.admin_delete_user(
            UserPoolId=_pool, Username=_user
        )
    )
    assert _user_status(cognito, pool_id, username) == "UNCONFIRMED", (
        "the user must start out awaiting confirmation for this check to say anything"
    )

    hashless_code, hashless_message = _rejection(
        lambda: cognito.confirm_sign_up(
            ClientId=client_id, Username=username, ConfirmationCode=NEVER_ISSUED_CODE
        )
    )
    assert hashless_code == "NotAuthorizedException", (
        f"expected the missing SecretHash to be refused first, got {hashless_code}: {hashless_message!r}"
    )
    assert hashless_message == f"Client {client_id} is configured with secret but SECRET_HASH was not received", (
        f"unexpected message for the hashless ConfirmSignUp: {hashless_message!r}"
    )
    assert _user_status(cognito, pool_id, username) == "UNCONFIRMED", (
        "the refused ConfirmSignUp must not have confirmed the user"
    )

    # The legal neighbour of the refused request: the hash is right, so the call now reaches the
    # code check, where no code was ever delivered for this user.
    hashed_code, hashed_message = _rejection(
        lambda: cognito.confirm_sign_up(
            ClientId=client_id,
            Username=username,
            ConfirmationCode=NEVER_ISSUED_CODE,
            SecretHash=_app_secret_hash(secret, username, client_id),
        )
    )
    assert hashed_code == "ExpiredCodeException", (
        f"with a valid SecretHash the code check must answer, got {hashed_code}: {hashed_message!r}"
    )
    assert hashed_message == "Invalid code provided, please request a code again.", (
        f"unexpected message for the code check: {hashed_message!r}"
    )
    assert _user_status(cognito, pool_id, username) == "UNCONFIRMED", (
        "the refused code must not have confirmed the user either"
    )

    # The user was confirmable all along, so neither refusal above was about the account.
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    assert _user_status(cognito, pool_id, username) == "CONFIRMED", (
        "AdminConfirmSignUp should leave the user CONFIRMED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
