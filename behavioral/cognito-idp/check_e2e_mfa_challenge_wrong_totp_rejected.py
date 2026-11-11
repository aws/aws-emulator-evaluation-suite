"""e2e-mfa-challenge-wrong-totp-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-mfa-challenge-wrong-totp-rejected"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A wrong TOTP in a SOFTWARE_TOKEN_MFA challenge fails with CodeMismatchException and its exact
    message and issues no tokens, and the correct code on the same session still signs the user in."""
    cognito = ctx.client("cognito-idp")
    password = "S1mple!Passw0rd"

    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-mfa-neg-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
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
        ClientName=ctx.unique_name("sim2real-mfa-neg-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-mfa-neg-user-")

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

    cognito.sign_up(ClientId=client_id, Username=username, Password=password)
    cognito.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    login1 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = login1["AuthenticationResult"]["AccessToken"]

    secret_code = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_code = _totp_now(secret_code)
    verify = cognito.verify_software_token(AccessToken=access_token, UserCode=verify_code)
    assert verify["Status"] == "SUCCESS"

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    login2 = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert login2.get("ChallengeName") == "SOFTWARE_TOKEN_MFA"
    session = login2["Session"]

    # Cognito rejects reuse of an already-consumed TOTP code (ExpiredCodeException), so the
    # correct code used below for both the mismatch construction and the positive control
    # must be a fresh one that has never been submitted (verify_code was already consumed).
    correct_code = _wait_for_new_totp(secret_code, verify_code)
    wrong_code = str((int(correct_code) + 1) % 1_000_000).zfill(6)

    def _bad_attempt():
        return cognito.admin_respond_to_auth_challenge(
            UserPoolId=pool_id,
            ClientId=client_id,
            ChallengeName="SOFTWARE_TOKEN_MFA",
            ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": wrong_code},
            Session=session,
        )

    error_payload = _rejection_response(_bad_attempt)
    code = error_payload["Error"]["Code"]
    assert code == "CodeMismatchException", (
        f"expected CodeMismatchException, got {code!r} (payload {error_payload!r})"
    )
    message = error_payload["Error"].get("Message", "")
    assert message == "Invalid code received for user", (
        f"expected the exact CodeMismatchException message 'Invalid code received for user', got {message!r}"
    )
    # effect absent: the mismatched attempt never produced an AuthenticationResult
    assert "AuthenticationResult" not in error_payload, (
        f"tokens accompanied the refused MFA code: {sorted(error_payload)!r}"
    )

    # positive control (same file, SAME session/challenge as the mismatched attempt): the
    # docstring's claim is that the wrong code did not consume or invalidate the challenge, so
    # the control must retry on that identical session rather than starting a fresh login --
    # a fresh login would still pass even if the original challenge had been silently burned.
    good = cognito.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="SOFTWARE_TOKEN_MFA",
        ChallengeResponses={"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": correct_code},
        Session=session,
    )
    assert "AuthenticationResult" in good, (
        f"the correct code was rejected on the SAME session the wrong code was rejected on, "
        f"so the challenge was consumed/invalidated by the earlier mismatch: {good!r}"
    )

    # terminal read is independent, at the destination: the issued token must actually work,
    # not merely be present in the mutating call's own response.
    new_access_token = good["AuthenticationResult"]["AccessToken"]
    who = cognito.get_user(AccessToken=new_access_token)
    assert who["Username"] == username, (
        f"the post-MFA access token is not usable against GetUser: {who!r}"
    )


def _totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
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


def _rejection_response(fn) -> dict:
    """Return the full botocore error response of a call expected to be REJECTED.

    Raises when the call succeeds, so an accepted call never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"the call was expected to be rejected but SUCCEEDED, which is the defect: {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
