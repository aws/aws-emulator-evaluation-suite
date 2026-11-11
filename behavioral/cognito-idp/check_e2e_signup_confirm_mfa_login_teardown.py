"""e2e-signup-confirm-mfa-login-teardown."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-signup-confirm-mfa-login-teardown"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A signed-up user with TOTP MFA signs in through the SOFTWARE_TOKEN_MFA challenge; after
    AdminDeleteUser both AdminGetUser and a fresh login fail with UserNotFoundException and its
    exact message."""
    cognito = ctx.client("cognito-idp")
    password = "S1mple!Passw0rd"

    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-mfa-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mfa"},
    )
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-mfa-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-mfa-user-")

    def _cleanup_user() -> None:
        try:
            cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "ResourceNotFoundException",
                "UserNotFoundException",
            ):
                raise

    ctx.on_cleanup(_cleanup_user)

    signup = cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    assert signup["UserConfirmed"] is False, (
        f"expected UserConfirmed False right after SignUp, got {signup['UserConfirmed']!r}"
    )

    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    status_after_confirm = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_after_confirm == "CONFIRMED", (
        f"expected CONFIRMED after AdminConfirmSignUp, got {status_after_confirm!r}"
    )

    # First login: no MFA enrolled yet, so AuthenticationResult is returned directly.
    login1 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in login1, (
        f"expected tokens from the pre-MFA login, got {login1!r}"
    )
    access_token = login1["AuthenticationResult"]["AccessToken"]

    secret_code = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]

    verify_code = _totp_now(secret_code)
    verify = cognito.verify_software_token(AccessToken=access_token, UserCode=verify_code)
    assert verify["Status"] == "SUCCESS", (
        f"expected VerifySoftwareToken SUCCESS, got {verify['Status']!r}"
    )

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # Second login must now present the enrolled software-token MFA challenge.
    login2 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert login2.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
        f"expected a SOFTWARE_TOKEN_MFA challenge now that MFA is enrolled and preferred, "
        f"got {login2.get('ChallengeName')!r}"
    )

    # Cognito rejects reuse of a TOTP code that has already been consumed (by
    # VerifySoftwareToken above) with ExpiredCodeException, so wait for the TOTP window to
    # advance before responding to the challenge with a fresh, never-consumed code.
    challenge_code = _wait_for_new_totp(secret_code, verify_code)
    challenge_result = cognito.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": challenge_code},
        Session=login2["Session"],
    )
    assert "AuthenticationResult" in challenge_result, (
        f"expected tokens after responding to the MFA challenge with a fresh TOTP code, "
        f"got {challenge_result!r}"
    )

    cognito.admin_delete_user(UserPoolId=pool_id, Username=username)

    read_code, read_message = _error(lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username))
    assert read_code == "UserNotFoundException", (
        f"expected UserNotFoundException reading the deleted user, got {read_code!r}"
    )
    assert read_message == "User does not exist.", (
        f"expected the exact UserNotFoundException message 'User does not exist.', got {read_message!r}"
    )

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


def _totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """RFC 6238 TOTP (SHA1) computed from the caller's current clock, matching Cognito's
    software-token MFA verification window."""
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _wait_for_new_totp(secret_b32: str, previous_code: str, *, period: int = 30, timeout_s: float = 40.0) -> str:
    """Cognito rejects reuse of an already-consumed TOTP code (ExpiredCodeException), so poll
    until the 30s TOTP window advances past `previous_code` and return the fresh code."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        code = _totp_now(secret_b32, period=period)
        if code != previous_code:
            return code
        time.sleep(1)
    raise AssertionError(f"TOTP window did not advance past {previous_code!r} within {timeout_s}s")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
