"""admin-mfa-preference-and-auth-factors."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "admin-mfa-preference-and-auth-factors"
GROUP = 'mfa-config'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"
_AUTH_FLOWS = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
]


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    """Compute an RFC 6238 TOTP code for the given base32 secret. ``offset`` shifts the time-step
    counter to tolerate small clock skew when verifying a freshly-associated software token."""
    import base64
    import hashlib
    import hmac
    import struct
    import time

    padded = secret_b32.upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // step) + offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    o = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[o : o + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _admin_login(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert "AuthenticationResult" in resp, f"expected AuthenticationResult, got a challenge: {resp}"
    return resp["AuthenticationResult"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserMFAPreference (admin surface) enrolls a verified software token as PREFERRED, and
    both GetUserAuthFactors (the signed-in user's own AccessToken) and AdminGetUserAuthFactors (the
    admin's UserPoolId/Username surface) reflect it consistently with the preferred/enrolled factor."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c, AutoVerifiedAttributes=["email"])
    client_id = _new_client(ctx, c, pool_id, ExplicitAuthFlows=list(_AUTH_FLOWS))["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    auth = _admin_login(c, pool_id, client_id, username, password)
    access_token = auth["AccessToken"]

    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_status = None
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = c.verify_software_token(
                AccessToken=access_token, UserCode=_totp_now(secret, offset=offset)
            )
            verify_status = resp["Status"]
            break
        except Exception:
            continue
    assert verify_status == "SUCCESS", "TOTP verification never succeeded"

    c.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # GetUserAuthFactors takes the signed-in user's own AccessToken; AdminGetUserAuthFactors takes
    # the admin's UserPoolId/Username. Both must reflect the same preferred/enrolled MFA factors.
    factors = c.get_user_auth_factors(AccessToken=access_token)
    assert factors.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", factors.get(
        "PreferredMfaSetting"
    )
    assert "SOFTWARE_TOKEN_MFA" in factors.get("UserMFASettingList", []), factors.get(
        "UserMFASettingList"
    )

    admin_factors = c.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert admin_factors.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", admin_factors.get(
        "PreferredMfaSetting"
    )
    assert "SOFTWARE_TOKEN_MFA" in admin_factors.get("UserMFASettingList", []), admin_factors.get(
        "UserMFASettingList"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
