"""set-user-mfa-preference-disable-clears-preferred-flag."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-disable-clears-preferred-flag"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disabling the preferred MFA method via SetUserMFAPreference clears
    PreferredMfaSetting in GetUserAuthFactors while the other enabled method
    (software token) remains enabled."""
    cidp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cidp)
    client_id = _create_client(ctx, cidp, pool_id)

    username = ctx.unique_name("sim2real-mfaclear-")
    password = "Sim2Real-Passw0rd!23"
    cidp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[
            {"Name": "phone_number", "Value": "+15555550123"},
            {"Name": "phone_number_verified", "Value": "true"},
        ],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cidp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    assoc = cidp.associate_software_token(AccessToken=access_token)
    code = _totp(assoc["SecretCode"])
    verify = cidp.verify_software_token(AccessToken=access_token, UserCode=code)
    assert verify["Status"] == "SUCCESS"

    # Activate both methods, SMS preferred.
    cidp.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": False},
        SMSMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    factors_before = cidp.get_user_auth_factors(AccessToken=access_token)
    assert factors_before["PreferredMfaSetting"] == "SMS_MFA"
    assert set(factors_before["UserMFASettingList"]) == {"SMS_MFA", "SOFTWARE_TOKEN_MFA"}

    # Disable the preferred method only.
    cidp.set_user_mfa_preference(
        AccessToken=access_token,
        SMSMfaSettings={"Enabled": False, "PreferredMfa": False},
    )

    factors_after = cidp.get_user_auth_factors(AccessToken=access_token)
    assert not factors_after.get("PreferredMfaSetting"), (
        f"expected preferred MFA to be cleared, got {factors_after.get('PreferredMfaSetting')!r}"
    )
    assert factors_after["UserMFASettingList"] == ["SOFTWARE_TOKEN_MFA"], (
        f"expected software token to remain the sole enabled MFA method, got {factors_after['UserMFASettingList']!r}"
    )


def _create_user_pool(ctx, cidp) -> str:
    resp = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real-check": CHECK},
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before any user's access token
    # can call AssociateSoftwareToken (otherwise SoftwareTokenMFANotFoundException).
    cidp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    return pool_id


def _create_client(ctx, cidp, pool_id: str) -> str:
    resp = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    return resp["UserPoolClient"]["ClientId"]


def _totp(secret_b32: str, digits: int = 6, interval: int = 30) -> str:
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
