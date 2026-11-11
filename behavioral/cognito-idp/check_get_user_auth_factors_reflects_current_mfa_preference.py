"""get-user-auth-factors-reflects-current-mfa-preference."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-auth-factors-reflects-current-mfa-preference"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserAuthFactors reflects the MFA preference set moments earlier by SetUserMFAPreference,
    both when a factor is enabled/preferred and when it is subsequently turned back off."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_password_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    _create_confirmed_user(ctx, pool_id, username)

    access_token = _sign_in(ctx, client_id, username)["AccessToken"]

    secret_code = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    _verify_software_token_with_retry(cognito, access_token, secret_code)

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    enabled_factors = cognito.get_user_auth_factors(AccessToken=access_token)
    assert enabled_factors["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting=SOFTWARE_TOKEN_MFA after enabling it, "
        f"got {enabled_factors['PreferredMfaSetting']!r}"
    )
    assert "SOFTWARE_TOKEN_MFA" in enabled_factors["UserMFASettingList"], (
        f"expected SOFTWARE_TOKEN_MFA in UserMFASettingList after enabling it, "
        f"got {enabled_factors['UserMFASettingList']!r}"
    )

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )
    disabled_factors = cognito.get_user_auth_factors(AccessToken=access_token)
    assert not disabled_factors.get("PreferredMfaSetting"), (
        f"expected PreferredMfaSetting cleared after disabling it, "
        f"got {disabled_factors.get('PreferredMfaSetting')!r}"
    )
    assert "SOFTWARE_TOKEN_MFA" not in disabled_factors.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA removed from UserMFASettingList after disabling it, "
        f"got {disabled_factors.get('UserMFASettingList')!r}"
    )


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    return pool_id


def _create_password_client(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username):
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_PASSWORD,
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _sign_in(ctx, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


def _totp_code(secret_b32: str, offset_steps: int = 0, digits: int = 6, period: int = 30) -> str:
    import base64
    import hashlib
    import hmac
    import struct
    import time

    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(time.time() // period) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _verify_software_token_with_retry(cognito, access_token, secret_code):
    # Tolerate a small amount of clock skew between this process and the Cognito TOTP
    # validator by trying a handful of adjacent 30s windows; no sleeping is involved.
    from botocore.exceptions import ClientError

    last_exc = None
    for offset in (0, -1, 1, -2, 2):
        code = _totp_code(secret_code, offset_steps=offset)
        try:
            return cognito.verify_software_token(AccessToken=access_token, UserCode=code)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "CodeMismatchException":
                raise
            last_exc = exc
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
