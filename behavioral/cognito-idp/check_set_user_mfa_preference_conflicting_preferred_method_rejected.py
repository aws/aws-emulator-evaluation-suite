"""set-user-mfa-preference-conflicting-preferred-method-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-conflicting-preferred-method-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Test123"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference rejects preferring software-token MFA before a TOTP authenticator is
    registered, leaving the preference unchanged; after registering, the identical call succeeds.
    """
    cognito = ctx.client("cognito-idp")
    pool_id, client_id, username = _setup_confirmed_user(ctx)
    access_token = _get_access_token(ctx, pool_id, client_id, username)

    def _attempt_preferred():
        return cognito.set_user_mfa_preference(
            AccessToken=access_token,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )

    code, message = _error(_attempt_preferred)
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    expected_message = "User does not have delivery config set to turn on SOFTWARE_TOKEN_MFA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no software-token preference got persisted
    factors = cognito.get_user_auth_factors(AccessToken=access_token)
    assert factors.get("PreferredMfaSetting") is None, (
        f"the rejected call set a preferred MFA method anyway: {factors!r}"
    )
    assert "SOFTWARE_TOKEN_MFA" not in factors.get("UserMFASettingList", []), (
        f"the rejected call activated software-token MFA anyway: {factors!r}"
    )

    # Registering a TOTP authenticator removes the one blocking condition.
    secret = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    _verify_totp_with_retry(cognito, access_token, secret)
    _attempt_preferred()

    factors_after = cognito.get_user_auth_factors(AccessToken=access_token)
    assert factors_after.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", (
        f"the identical call did not succeed once a TOTP authenticator was registered: "
        f"{factors_after!r}"
    )
    assert "SOFTWARE_TOKEN_MFA" in factors_after.get("UserMFASettingList", []), (
        f"software-token MFA is not listed as an active setting after the restore: "
        f"{factors_after!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _totp(secret_b32: str, offset_steps: int = 0) -> str:
    """RFC 6238 TOTP, SHA1/6-digit/30s step -- matches Cognito's software token algorithm."""
    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // 30) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def _verify_totp_with_retry(cognito, access_token, secret):
    last_error = None
    for offset in (0, -1, 1, -2, 2):
        code = _totp(secret, offset)
        try:
            resp = cognito.verify_software_token(AccessToken=access_token, UserCode=code)
            if resp.get("Status") == "SUCCESS":
                return
        except ClientError as exc:  # wrong 30s time window, try the next offset
            last_error = exc
            continue
    raise AssertionError(f"VerifySoftwareToken never succeeded within the retry window: {last_error}")


def _setup_confirmed_user(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before AssociateSoftwareToken
    # works (otherwise SoftwareTokenMFANotFoundException) -- the rejection under test is
    # about the *user* never having registered a token, not about the pool lacking the feature.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=_PASSWORD,
        MessageAction="SUPPRESS",
        UserAttributes=[
            {"Name": "email", "Value": f"{username}@example.com"},
            {"Name": "email_verified", "Value": "true"},
        ],
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    return pool_id, client_id, username


def _get_access_token(ctx, pool_id, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
