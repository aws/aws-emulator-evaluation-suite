"""associate-verify-software-token-enables-mfa."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "associate-verify-software-token-enables-mfa"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSoftwareToken+VerifySoftwareToken registers a TOTP factor that shows up via
    GetUserAuthFactors/AdminGetUserAuthFactors, SetUserMFAPreference/AdminSetUserMFAPreference
    activates it, and AdminDeleteSoftwareToken revokes it (factor disappears again)."""
    cog = ctx.client("cognito-idp")
    password = "Sim2RealP@ss9142"

    pool_id = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-totp-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cog.delete_user_pool(UserPoolId=pool_id))

    cog.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    client_id = cog.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-totp-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("totpuser-")
    cog.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cog.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cog.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # Baseline: no software token factor configured yet.
    baseline = cog.get_user_auth_factors(AccessToken=access_token)
    assert "SOFTWARE_TOKEN_MFA" not in baseline.get("UserMFASettingList", []), (
        f"expected no SOFTWARE_TOKEN_MFA factor before enrollment, got {baseline.get('UserMFASettingList')}"
    )

    secret_code = cog.associate_software_token(AccessToken=access_token)["SecretCode"]

    verify_status = None
    last_error = None
    for offset in (0, -1, 1, -2, 2):
        code = _totp(secret_code, offset)
        try:
            verify_status = cog.verify_software_token(AccessToken=access_token, UserCode=code)["Status"]
            break
        except cog.exceptions.CodeMismatchException as exc:  # wrong 30s time window, try next offset
            last_error = exc
            continue
    if verify_status is None:
        raise AssertionError(f"VerifySoftwareToken never succeeded: {last_error}")
    assert verify_status == "SUCCESS", f"expected VerifySoftwareToken Status SUCCESS, got {verify_status}"

    cog.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    factors = cog.get_user_auth_factors(AccessToken=access_token)
    assert factors["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting SOFTWARE_TOKEN_MFA, got {factors['PreferredMfaSetting']}"
    )
    assert "SOFTWARE_TOKEN_MFA" in factors["UserMFASettingList"], (
        f"expected SOFTWARE_TOKEN_MFA in UserMFASettingList, got {factors['UserMFASettingList']}"
    )
    assert "SOFTWARE_TOKEN" in factors["ConfiguredUserAuthFactors"], (
        f"expected SOFTWARE_TOKEN in ConfiguredUserAuthFactors, got {factors['ConfiguredUserAuthFactors']}"
    )

    admin_factors = cog.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert admin_factors["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", (
        f"expected admin-side PreferredMfaSetting SOFTWARE_TOKEN_MFA, got {admin_factors['PreferredMfaSetting']}"
    )
    assert "SOFTWARE_TOKEN_MFA" in admin_factors["UserMFASettingList"], (
        f"expected SOFTWARE_TOKEN_MFA in admin-side UserMFASettingList, got {admin_factors['UserMFASettingList']}"
    )

    # AdminSetUserMFAPreference re-asserts the same activation from the admin side.
    cog.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    reconfirmed = cog.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert reconfirmed["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting SOFTWARE_TOKEN_MFA after AdminSetUserMFAPreference reconfirm, "
        f"got {reconfirmed['PreferredMfaSetting']}"
    )

    # AdminDeleteSoftwareToken revokes the factor; it must disappear from both views.
    cog.admin_delete_software_token(UserPoolId=pool_id, Username=username)

    after_delete = cog.get_user_auth_factors(AccessToken=access_token)
    assert "SOFTWARE_TOKEN_MFA" not in after_delete.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA gone from UserMFASettingList after delete, got {after_delete.get('UserMFASettingList')}"
    )
    assert after_delete.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting no longer SOFTWARE_TOKEN_MFA after delete, got {after_delete.get('PreferredMfaSetting')}"
    )
    assert "SOFTWARE_TOKEN" not in after_delete.get("ConfiguredUserAuthFactors", []), (
        f"expected SOFTWARE_TOKEN gone from ConfiguredUserAuthFactors after delete, got {after_delete.get('ConfiguredUserAuthFactors')}"
    )

    admin_after_delete = cog.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" not in admin_after_delete.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA gone from admin-side UserMFASettingList after delete, "
        f"got {admin_after_delete.get('UserMFASettingList')}"
    )


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
