"""set-user-mfa-preference-idempotent-reapply."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "set-user-mfa-preference-idempotent-reapply"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserMFAPreference with the same software-token payload succeeds twice, and after each call
    SOFTWARE_TOKEN_MFA is the preferred and listed MFA setting."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=dict(_POOL_TAGS)
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before any user's access
    # token can call AssociateSoftwareToken (otherwise SoftwareTokenMFANotFoundException).
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-behav-user-")
    password = "Sim2Real-Behav-Pw1!"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    access_token = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    secret_code = idp.associate_software_token(AccessToken=access_token)["SecretCode"]
    _verify_software_token_with_retry(idp, access_token, secret_code)

    # Enrolling software-token MFA is the real state change under test -- unlike the
    # pool's default (no MFA enabled), a redundant re-apply of this payload has
    # something to actually disturb if the target mishandles it.
    payload = {"SoftwareTokenMfaSettings": {"Enabled": True, "PreferredMfa": True}}

    first = idp.set_user_mfa_preference(AccessToken=access_token, **payload)
    assert first["ResponseMetadata"]["HTTPStatusCode"] == 200, first

    factors_after_first = idp.get_user_auth_factors(AccessToken=access_token)
    assert factors_after_first["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", factors_after_first
    assert "SOFTWARE_TOKEN_MFA" in factors_after_first["UserMFASettingList"], factors_after_first

    # Re-applying the identical, already-current preference must not raise, and must
    # leave the preference exactly as it already was.
    second = idp.set_user_mfa_preference(AccessToken=access_token, **payload)
    assert second["ResponseMetadata"]["HTTPStatusCode"] == 200, second

    factors_after_second = idp.get_user_auth_factors(AccessToken=access_token)
    assert factors_after_second["PreferredMfaSetting"] == "SOFTWARE_TOKEN_MFA", factors_after_second
    assert "SOFTWARE_TOKEN_MFA" in factors_after_second["UserMFASettingList"], factors_after_second


def _totp_code(secret_b32: str, offset_steps: int = 0, digits: int = 6, period: int = 30) -> str:
    padded = secret_b32.upper() + "=" * (-len(secret_b32) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _verify_software_token_with_retry(idp, access_token, secret_code):
    # Tolerate a small amount of clock skew between this process and the Cognito TOTP
    # validator by trying a handful of adjacent 30s windows; no sleeping is involved.
    from botocore.exceptions import ClientError

    last_exc = None
    for offset in (0, -1, 1, -2, 2):
        code = _totp_code(secret_code, offset_steps=offset)
        try:
            resp = idp.verify_software_token(AccessToken=access_token, UserCode=code)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "CodeMismatchException":
                raise
            last_exc = exc
            continue
        assert resp["Status"] == "SUCCESS", resp
        return resp
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
