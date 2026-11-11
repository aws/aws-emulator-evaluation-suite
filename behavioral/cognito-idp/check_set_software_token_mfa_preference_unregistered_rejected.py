"""set-software-token-mfa-preference-unregistered-rejected."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-software-token-mfa-preference-unregistered-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference enabling software-token MFA for a user with no TOTP authenticator fails with
    InvalidParameterException and its exact message and leaves MFA unset; after AssociateSoftwareToken and
    VerifySoftwareToken the same call makes SOFTWARE_TOKEN_MFA preferred."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx, cognito)
    access_token = _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id)

    code, message = _error(
        lambda: cognito.set_user_mfa_preference(
            AccessToken=access_token,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for enabling TOTP MFA before registering a "
        f"software token, got {code}"
    )
    expected_message = "User does not have delivery config set to turn on SOFTWARE_TOKEN_MFA"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: no MFA setting was recorded for the user.
    user = cognito.get_user(AccessToken=access_token)
    assert user.get("UserMFASettingList", []) == [], (
        f"the rejected SetUserMFAPreference call must not record any MFA setting, "
        f"got UserMFASettingList={user.get('UserMFASettingList')!r}"
    )
    assert user.get("PreferredMfaSetting") is None, (
        f"the rejected SetUserMFAPreference call must not set a preferred MFA method, "
        f"got PreferredMfaSetting={user.get('PreferredMfaSetting')!r}"
    )

    # Positive control: after registering (associate + verify) a TOTP authenticator,
    # the identical SetUserMFAPreference call succeeds.
    secret = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    _verify_totp_with_retry(cognito, access_token, secret)
    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    user_after = cognito.get_user(AccessToken=access_token)
    assert user_after.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting=SOFTWARE_TOKEN_MFA once the identical call is retried "
        f"after registering a TOTP authenticator, got {user_after.get('PreferredMfaSetting')!r}"
    )
    assert "SOFTWARE_TOKEN_MFA" in user_after.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA in UserMFASettingList once registered, "
        f"got {user_after.get('UserMFASettingList')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _totp(secret_b32: str, for_time: float, digits: int = 6, interval: int = 30) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def _verify_totp_with_retry(cognito, access_token: str, secret: str) -> None:
    last_exc = None
    for attempt in range(3):
        code = _totp(secret, time.time() + attempt * 30)
        try:
            resp = cognito.verify_software_token(AccessToken=access_token, UserCode=code)
            if resp.get("Status") == "SUCCESS":
                return
        except Exception as exc:
            last_exc = exc
            time.sleep(1)
    raise AssertionError(f"could not verify software token after retries: {last_exc}")


def _create_pool_and_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-negmfapool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before any user can
    # AssociateSoftwareToken (otherwise SoftwareTokenMFANotFoundException) -- the
    # rejection under test is about the *user* never having registered a token,
    # not about the pool lacking the feature.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-negmfaclient-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id) -> str:
    username = ctx.unique_name("sim2real-behav-negmfauser-")
    password = "Sim2Real!Behav0r123"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
