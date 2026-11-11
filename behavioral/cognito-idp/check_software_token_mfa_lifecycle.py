"""software-token-mfa-lifecycle."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "software-token-mfa-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSoftwareToken->VerifySoftwareToken enables TOTP MFA, the preference is
    set via SetUserMFAPreference/AdminSetUserMFAPreference, and AdminDeleteSoftwareToken
    tears the token down and disables MFA for the user."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_user_pool(idp, pool_id))
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

    baseline = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" not in baseline.get("UserMFASettingList", []), (
        f"expected no software-token factor before enrollment, got {baseline.get('UserMFASettingList')}"
    )

    secret_code = idp.associate_software_token(AccessToken=access_token)["SecretCode"]
    verify_resp = _verify_software_token_with_retry(idp, access_token, secret_code)
    assert verify_resp["Status"] == "SUCCESS", f"expected VerifySoftwareToken SUCCESS, got {verify_resp}"

    idp.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    # AdminGetUser can lag a SetUserMFAPreference write briefly; poll rather than read once.
    _poll_admin_get_user(
        idp,
        pool_id,
        username,
        lambda u: "SOFTWARE_TOKEN_MFA" in u.get("UserMFASettingList", []),
        "SOFTWARE_TOKEN_MFA to appear in UserMFASettingList after SetUserMFAPreference",
    )

    idp.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    _poll_admin_get_user(
        idp,
        pool_id,
        username,
        lambda u: u.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA",
        "PreferredMfaSetting to become SOFTWARE_TOKEN_MFA after AdminSetUserMFAPreference",
    )

    idp.admin_delete_software_token(UserPoolId=pool_id, Username=username)

    after = _poll_admin_get_user(
        idp,
        pool_id,
        username,
        lambda u: "SOFTWARE_TOKEN_MFA" not in u.get("UserMFASettingList", []),
        "SOFTWARE_TOKEN_MFA to disappear from UserMFASettingList after AdminDeleteSoftwareToken",
    )
    assert after.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting cleared after AdminDeleteSoftwareToken, got {after.get('PreferredMfaSetting')}"
    )


def _delete_user_pool(idp, pool_id: str) -> None:
    """A pool created with deletion protection active rejects DeleteUserPool outright;
    disable it first so cleanup does not silently orphan the pool."""
    try:
        idp.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    idp.delete_user_pool(UserPoolId=pool_id)


def _totp(secret_b32: str, digits: int = 6, period: int = 30, step_offset: int = 0) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(time.time() // period) + step_offset
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def _verify_software_token_with_retry(idp, access_token: str, secret_code: str) -> dict:
    """The code and the request that carries it can straddle a 30s TOTP window boundary."""
    last_error = None
    for step_offset in (0, -1, 1, -2, 2):
        code = _totp(secret_code, step_offset=step_offset)
        try:
            return idp.verify_software_token(AccessToken=access_token, UserCode=code)
        except idp.exceptions.CodeMismatchException as exc:
            last_error = exc
    raise AssertionError(f"VerifySoftwareToken never accepted a code across the retry window: {last_error}")


def _poll_admin_get_user(idp, pool_id: str, username: str, predicate, description: str, timeout: float = 15.0, interval: float = 1.0) -> dict:
    deadline = time.time() + timeout
    while True:
        result = idp.admin_get_user(UserPoolId=pool_id, Username=username)
        if predicate(result):
            return result
        if time.time() >= deadline:
            raise AssertionError(f"timed out waiting for {description}; last read: {result}")
        time.sleep(interval)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
