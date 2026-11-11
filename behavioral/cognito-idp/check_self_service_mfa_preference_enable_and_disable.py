"""self-service-mfa-preference-enable-and-disable."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "self-service-mfa-preference-enable-and-disable"
GROUP = 'mfa-configuration'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _totp_now(secret_b32, digits=6, step=30, offset=0):
    """RFC 6238 TOTP code for a base32 secret."""
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a verified software token, SetUserMFAPreference enabling it shows in
    GetUserAuthFactors and AdminGetUser's UserMFASettingList, and disabling it removes it again:
    the preference toggles both ways."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    access_token = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]["AccessToken"]

    secret = c.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_status = None
    last_error = None
    # Try adjacent TOTP windows to tolerate clock skew between client and service.
    for offset in (0, -1, 1, -2, 2):
        try:
            resp = c.verify_software_token(AccessToken=access_token, UserCode=_totp_now(secret, offset=offset))
            verify_status = resp["Status"]
            break
        except ClientError as exc:
            last_error = exc.response["Error"]["Code"]
            if last_error != "CodeMismatchException":
                raise
    assert verify_status == "SUCCESS", f"TOTP verification never succeeded, last error={last_error!r}"

    c.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    factors_on = c.get_user_auth_factors(AccessToken=access_token)
    assert factors_on.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", factors_on
    settings_on = c.admin_get_user(UserPoolId=pool_id, Username=username).get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" in settings_on, settings_on

    c.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
    )
    factors_off = c.get_user_auth_factors(AccessToken=access_token)
    assert factors_off.get("PreferredMfaSetting") is None, factors_off
    settings_off = c.admin_get_user(UserPoolId=pool_id, Username=username).get("UserMFASettingList", [])
    assert "SOFTWARE_TOKEN_MFA" not in settings_off, settings_off


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
