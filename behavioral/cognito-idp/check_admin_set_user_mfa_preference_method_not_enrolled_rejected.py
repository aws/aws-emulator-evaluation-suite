"""admin-set-user-mfa-preference-method-not-enrolled-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-method-not-enrolled-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference preferring SOFTWARE_TOKEN_MFA for a user without a TOTP secret is
    refused with InvalidParameterException and the exact message and changes nothing; after the user
    verifies a software token, the same call makes it preferred."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-mfapref-pool-"))[
        "UserPool"
    ]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA is enabled on the pool (AssociateSoftwareToken needs it), so the rejection
    # below is about the user never having registered a token, not the pool lacking the feature.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-mfapref-client-"),
        ExplicitAuthFlows=list(_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-mfapref-user-")
    password = "TestPassw0rd!23"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    baseline = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert baseline.get("PreferredMfaSetting") is None, baseline.get("PreferredMfaSetting")

    def _attempt_preferred_totp():
        cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )

    code, message = _error(_attempt_preferred_totp)
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for preferring an unenrolled TOTP factor, got {code!r}"
    )
    expected_message = "User does not have delivery config set to turn on SOFTWARE_TOKEN_MFA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    after_bad = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_bad.get("PreferredMfaSetting") is None, after_bad.get("PreferredMfaSetting")
    assert "SOFTWARE_TOKEN_MFA" not in (after_bad.get("UserMFASettingList") or []), after_bad.get(
        "UserMFASettingList"
    )

    # Remove the one blocking condition: register a TOTP authenticator for this user.
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    secret = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_status = None
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = cognito.verify_software_token(
                AccessToken=access_token, UserCode=_totp_now(secret, offset=offset)
            )
            verify_status = resp["Status"]
            break
        except ClientError:
            continue
    assert verify_status == "SUCCESS", "TOTP verification never succeeded"

    # Positive control: the IDENTICAL AdminSetUserMFAPreference call now succeeds.
    _attempt_preferred_totp()
    after_good = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after_good.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", after_good.get(
        "PreferredMfaSetting"
    )
    assert "SOFTWARE_TOKEN_MFA" in (after_good.get("UserMFASettingList") or []), after_good.get(
        "UserMFASettingList"
    )


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    """RFC 6238 TOTP for the given base32 secret; ``offset`` shifts the time-step counter to
    tolerate small clock skew when verifying a freshly-associated software token."""
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
