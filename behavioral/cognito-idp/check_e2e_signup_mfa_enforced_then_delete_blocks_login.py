"""e2e-signup-mfa-enforced-then-delete-blocks-login."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-signup-mfa-enforced-then-delete-blocks-login"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A signed-up user with TOTP MFA is challenged with SOFTWARE_TOKEN_MFA; after AdminDeleteUser
    both AdminGetUser and a login fail with UserNotFoundException and its exact message."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx, cognito)
    client_id = _create_client(ctx, cognito, pool_id)

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real123"

    signup = cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    assert signup["UserConfirmed"] is False, (
        f"expected a fresh SignUp to leave the user unconfirmed, got UserConfirmed={signup['UserConfirmed']!r}"
    )

    # Self-service ConfirmSignUp requires the real confirmation code delivered out of
    # band (email/SMS), which this harness cannot receive; AdminConfirmSignUp performs
    # the identical UNCONFIRMED->CONFIRMED transition without that code.
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after AdminConfirmSignUp, got {status!r}"

    login1 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = login1["AuthenticationResult"]["AccessToken"]

    assoc = cognito.associate_software_token(AccessToken=access_token)
    secret_code = assoc["SecretCode"]
    _verify_software_token_with_retry(cognito, access_token, secret_code)

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    prefs = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    mfa_list = prefs.get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" in mfa_list, (
        f"expected SOFTWARE_TOKEN_MFA in UserMFASettingList after enabling it, got {mfa_list!r}"
    )

    # Positive control: MFA is now enforced, so a plain password login must stop at a
    # SOFTWARE_TOKEN_MFA challenge rather than returning tokens directly.
    login2 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    challenge = login2.get("ChallengeName")
    assert challenge == "SOFTWARE_TOKEN_MFA", (
        f"expected the enforced-MFA login to stop at a SOFTWARE_TOKEN_MFA challenge, got {challenge!r}"
    )

    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)

    # Independent read: the user is gone from the directory itself, not merely from auth.
    get_code, get_message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert get_code == "UserNotFoundException", (
        f"expected AdminGetUser to 404 after AdminDeleteUser, got {get_code!r}"
    )
    assert get_message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {get_message!r}"
    )

    # The independent-read consequence this check exists to prove: deletion doesn't just
    # remove the directory entry, it makes the exact same login that worked earlier fail.
    login_code, login_message = _error(
        lambda: cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert login_code == "UserNotFoundException", (
        f"expected login for the deleted user to fail with UserNotFoundException, got {login_code!r}"
    )
    assert login_message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {login_message!r}"
    )


def _create_pool(ctx, cognito) -> str:
    resp = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": False,
            }
        },
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_pool(cognito, pool_id))
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    return pool_id


def _create_client(ctx, cognito, pool_id: str) -> str:
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    return resp["UserPoolClient"]["ClientId"]


def _safe_delete_pool(cognito, pool_id: str) -> None:
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except cognito.exceptions.ResourceNotFoundException:
        pass


def _totp_code(secret_b32: str, offset_steps: int = 0, step: int = 30, digits: int = 6) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _verify_software_token_with_retry(cognito, access_token: str, secret_code: str) -> None:
    last_exc = None
    for offset_steps in (0, -1, 1):
        try:
            resp = cognito.verify_software_token(
                AccessToken=access_token, UserCode=_totp_code(secret_code, offset_steps)
            )
            assert resp["Status"] == "SUCCESS", f"expected VerifySoftwareToken to succeed, got Status={resp['Status']!r}"
            return
        except cognito.exceptions.CodeMismatchException as exc:  # pragma: no cover - clock skew
            last_exc = exc
    raise AssertionError(f"could not verify software token within +-1 step: {last_exc}")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
