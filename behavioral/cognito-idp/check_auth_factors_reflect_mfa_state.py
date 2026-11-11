"""auth-factors-reflect-mfa-state."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "auth-factors-reflect-mfa-state"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminGetUserAuthFactors/GetUserAuthFactors list only the MFA factors currently
    enabled for the user, and the list updates as factors are enabled/disabled."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Str0ng!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    before_self = idp.get_user_auth_factors(AccessToken=access_token)
    before_admin = idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" not in before_self.get("UserMFASettingList", []), (
        f"expected no MFA factors before setup, GetUserAuthFactors returned {before_self.get('UserMFASettingList')}"
    )
    assert "SOFTWARE_TOKEN_MFA" not in before_admin.get("UserMFASettingList", []), (
        f"expected no MFA factors before setup, AdminGetUserAuthFactors returned {before_admin.get('UserMFASettingList')}"
    )

    secret_code = idp.associate_software_token(AccessToken=access_token)["SecretCode"]
    idp.verify_software_token(
        AccessToken=access_token, UserCode=_totp(secret_code), FriendlyDeviceName="behavioral-check-token"
    )
    idp.set_user_mfa_preference(
        AccessToken=access_token, SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True}
    )

    after_enable_self = idp.get_user_auth_factors(AccessToken=access_token)
    after_enable_admin = idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" in after_enable_self.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA in GetUserAuthFactors after enable, got {after_enable_self.get('UserMFASettingList')}"
    )
    assert "SOFTWARE_TOKEN_MFA" in after_enable_admin.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA in AdminGetUserAuthFactors after enable, got {after_enable_admin.get('UserMFASettingList')}"
    )
    assert after_enable_self.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting=SOFTWARE_TOKEN_MFA after enable, got {after_enable_self.get('PreferredMfaSetting')!r}"
    )

    idp.set_user_mfa_preference(AccessToken=access_token, SoftwareTokenMfaSettings={"Enabled": False})

    after_disable_self = idp.get_user_auth_factors(AccessToken=access_token)
    after_disable_admin = idp.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" not in after_disable_self.get("UserMFASettingList", []), (
        f"expected no MFA factors after disable, GetUserAuthFactors returned {after_disable_self.get('UserMFASettingList')}"
    )
    assert "SOFTWARE_TOKEN_MFA" not in after_disable_admin.get("UserMFASettingList", []), (
        f"expected no MFA factors after disable, AdminGetUserAuthFactors returned {after_disable_admin.get('UserMFASettingList')}"
    )


def _totp(secret_b32: str, digits: int = 6, period: int = 30, for_time: float | None = None) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int((for_time or time.time()) // period)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
