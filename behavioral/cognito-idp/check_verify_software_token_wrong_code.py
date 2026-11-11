"""verify-software-token-wrong-code."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "verify-software-token-wrong-code"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd1"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """VerifySoftwareToken with a wrong TOTP fails with EnableSoftwareTokenMFAException "Code mismatch" or
    answers Status ERROR, and enabling MFA then fails with InvalidParameterException and its exact
    message; the correct code then succeeds and SOFTWARE_TOKEN_MFA is listed."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    # Real Cognito rejects AssociateSoftwareToken with SoftwareTokenMFANotFoundException
    # ("Software Token MFA has not been enabled by the userPool") until the pool has
    # software-token MFA explicitly turned on.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    username = ctx.unique_name("sim2real-user-")
    _admin_create_confirmed_user(ctx, pool_id, username, _PASSWORD)
    auth = _admin_login(ctx, pool_id, client_id, username, _PASSWORD)
    access_token = auth["AccessToken"]

    assoc = cognito.associate_software_token(AccessToken=access_token)
    secret_code = assoc["SecretCode"]
    assert len(secret_code) >= 16

    # Derive an always-wrong code from the real secret (never the correct value for any
    # time step) instead of a literal "000000", which a positive-only target could pass
    # by fluke and which does not, on its own, rule out a target that rejects every
    # VerifySoftwareToken call regardless of the code.
    correct_code = _totp_now(secret_code)
    wrong_code = str((int(correct_code) + 1) % 1_000_000).zfill(6)

    try:
        resp = cognito.verify_software_token(AccessToken=access_token, UserCode=wrong_code)
    except ClientError as e:
        # Real Cognito's VerifySoftwareToken API does not model a CodeMismatchException;
        # a mismatched TOTP code during the AccessToken-based setup flow is instead
        # surfaced as EnableSoftwareTokenMFAException ("...code mismatch and the service
        # fails to configure the software token TOTP multi-factor authentication").
        code = e.response["Error"]["Code"]
        assert code == "EnableSoftwareTokenMFAException", (
            f"expected EnableSoftwareTokenMFAException, got {code}"
        )
        message = e.response["Error"].get("Message")
        assert message == "Code mismatch", (
            f"expected message 'Code mismatch', got {message!r}"
        )
    else:
        assert resp.get("Status") == "ERROR", (
            f"expected a Status='ERROR' response for a mismatched code, got {resp.get('Status')}"
        )

    # Effect absent: the rejected attempt did not register a usable software token.
    # VerifySoftwareToken succeeding is a prerequisite for SetUserMFAPreference to accept
    # SOFTWARE_TOKEN_MFA -- real Cognito's UserMFASettingList is driven by SetUserMFAPreference,
    # not by VerifySoftwareToken alone, so probing SetUserMFAPreference (rather than re-reading
    # UserMFASettingList, which would read the same regardless of whether verification had
    # succeeded) is the independent read that actually depends on the rejected code.
    def _enable() -> None:
        cognito.set_user_mfa_preference(
            AccessToken=access_token,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )

    code, message = _error(_enable)
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException enabling MFA without a verified token, got {code}"
    )
    expected = "User has not verified software token mfa"
    assert message == expected, (
        f"enabling MFA without a verified token: expected message {expected!r}, got {message!r}"
    )
    user = cognito.get_user(AccessToken=access_token)
    mfa_list = user.get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" not in mfa_list, f"MFA should not be enabled, got {mfa_list}"

    # Positive control, same API: a fresh (never-submitted) TOTP code for the same secret is
    # accepted, and the identical SetUserMFAPreference call now succeeds. Without this leg,
    # "rejects a wrong code" cannot be told apart from "rejects every VerifySoftwareToken call".
    final_code = _totp_now(secret_code)
    final = cognito.verify_software_token(AccessToken=access_token, UserCode=final_code)
    assert final.get("Status") == "SUCCESS", (
        f"expected SUCCESS for the correct TOTP code, got {final.get('Status')}"
    )
    _enable()
    after = cognito.get_user(AccessToken=access_token)
    after_list = after.get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" in after_list, f"MFA should be enabled after the correct code, got {after_list}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-pool-"))
    pool_id = pool["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )
    client_id = client["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _admin_create_confirmed_user(ctx, pool_id, username, password, email=None, email_verified=False):
    cognito = ctx.client("cognito-idp")
    attrs = []
    if email:
        attrs.append({"Name": "email", "Value": email})
        if email_verified:
            attrs.append({"Name": "email_verified", "Value": "true"})
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=attrs,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_login(ctx, pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _totp_now(secret_b32: str, digits: int = 6, period: int = 30) -> str:
    """RFC 6238 TOTP, SHA1/6-digit/30s step -- matches Cognito's software token algorithm."""
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
