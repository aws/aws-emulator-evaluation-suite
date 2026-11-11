"""mfa-preference-reflected-in-auth-factors."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-preference-reflected-in-auth-factors"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference / AdminSetUserMFAPreference are reflected by the GetUserAuthFactors APIs."""
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)

    access_token = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    # Software token MFA must be turned on at the pool level before a user can associate one;
    # real AWS rejects AssociateSoftwareToken with SoftwareTokenMFANotFoundException otherwise.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    secret = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_status = _verify_with_retry(cognito, access_token, secret)
    assert verify_status == "SUCCESS", verify_status

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    # SetUserMFAPreference's effect on GetUserAuthFactors can lag briefly on real AWS; poll for it.
    # ConfiguredUserAuthFactors names the TOTP MFA choice "SOFTWARE_TOKEN" (not "SOFTWARE_TOKEN_MFA",
    # which is only used in PreferredMfaSetting/UserMFASettingList).
    factors = _poll_until_auth_factors(
        lambda: cognito.get_user_auth_factors(AccessToken=access_token),
        lambda f: f.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA"
        and "SOFTWARE_TOKEN" in f.get("ConfiguredUserAuthFactors", []),
    )
    assert factors["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", factors
    assert "SOFTWARE_TOKEN" in factors["ConfiguredUserAuthFactors"], factors

    admin_factors = _poll_until_auth_factors(
        lambda: cognito.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username),
        lambda f: f.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA",
    )
    assert admin_factors["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", admin_factors

    cognito.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": False},
    )

    admin_factors_after = _poll_until_auth_factors(
        lambda: cognito.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username),
        lambda f: f.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA",
    )
    assert admin_factors_after.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA", admin_factors_after
    assert "SOFTWARE_TOKEN" in admin_factors_after["ConfiguredUserAuthFactors"], admin_factors_after

    factors_after = _poll_until_auth_factors(
        lambda: cognito.get_user_auth_factors(AccessToken=access_token),
        lambda f: f.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA",
    )
    assert factors_after.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA", factors_after


def _verify_with_retry(cognito, access_token: str, secret_b32: str) -> str:
    last_status = None
    for step_offset in (0, -1, 1, 2):
        code = _totp_code(secret_b32, step_offset)
        try:
            resp = cognito.verify_software_token(AccessToken=access_token, UserCode=code)
            return resp["Status"]
        except ClientError as exc:
            last_status = exc.response["Error"]["Code"]
            if last_status != "CodeMismatchException":
                raise
    raise AssertionError(f"no TOTP window matched; last error={last_status}")


def _totp_code(secret_b32: str, step_offset: int = 0) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // 30) + step_offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{truncated % 1000000:06d}"


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _poll_until_auth_factors(fetch, predicate, timeout: float = 15.0, interval: float = 1.0) -> dict:
    deadline = time.time() + timeout
    last = fetch()
    while not predicate(last):
        if time.time() >= deadline:
            raise AssertionError(f"auth factors did not reach expected state within {timeout}s: {last}")
        time.sleep(interval)
        last = fetch()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
