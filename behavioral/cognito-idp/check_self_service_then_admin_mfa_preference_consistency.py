"""self-service-then-admin-mfa-preference-consistency."""
from __future__ import annotations

import base64
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "self-service-then-admin-mfa-preference-consistency"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a user calls SetUserMFAPreference to prefer TOTP, a subsequent
    AdminSetUserMFAPreference by an admin that un-prefers it is reflected
    consistently in GetUserAuthFactors."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx, cognito)
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    client_id = _create_client(ctx, cognito, pool_id)
    username = ctx.unique_name("sim2real-behav-mfa-user-")
    password = "P@ssw0rd12345!"
    _create_confirmed_user(cognito, pool_id, username, password)
    access_token = _sign_in(cognito, pool_id, client_id, username, password)

    secret_code = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    user_code = _totp(secret_code)
    verify = cognito.verify_software_token(
        AccessToken=access_token, UserCode=user_code, FriendlyDeviceName="sim2real-authenticator"
    )
    assert verify["Status"] == "SUCCESS", verify

    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )
    after_self_service = _poll_auth_factors(
        cognito, access_token, lambda f: f.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA"
    )
    assert after_self_service.get("PreferredMfaSetting") == "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting=SOFTWARE_TOKEN_MFA after self-service opt-in, got {after_self_service}"
    )
    assert "SOFTWARE_TOKEN_MFA" in after_self_service.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA enrolled after self-service opt-in, got {after_self_service}"
    )

    cognito.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": False},
    )
    after_admin = _poll_auth_factors(
        cognito, access_token, lambda f: f.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA"
    )
    assert after_admin.get("PreferredMfaSetting") != "SOFTWARE_TOKEN_MFA", (
        f"expected PreferredMfaSetting no longer SOFTWARE_TOKEN_MFA after admin un-prefer, got {after_admin}"
    )
    assert "SOFTWARE_TOKEN_MFA" in after_admin.get("UserMFASettingList", []), (
        f"expected SOFTWARE_TOKEN_MFA to remain enrolled (only un-preferred, not disabled) after "
        f"admin un-prefer, got {after_admin}"
    )

    cognito.delete_user_pool(UserPoolId=pool_id)
    code, message = _error(lambda: cognito.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"expected pool {pool_id} gone (ResourceNotFoundException) after DeleteUserPool, got {code}"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_pool(ctx, cognito) -> str:
    name = ctx.unique_name("sim2real-behav-mfa-pool-")
    pool_id = cognito.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_idempotent(cognito, pool_id))
    return pool_id


def _delete_pool_idempotent(cognito, pool_id: str) -> None:
    """The check deletes its pool inline to grade the deletion; this cleanup only covers an
    earlier failure, so a pool that is already gone is not a teardown error."""
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_client(ctx, cognito, pool_id: str) -> str:
    name = ctx.unique_name("sim2real-behav-mfa-client-")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=name,
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(cognito, pool_id: str, username: str, password: str) -> None:
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rary!Pass",
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _sign_in(cognito, pool_id: str, client_id: str, username: str, password: str) -> str:
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


def _poll_auth_factors(cognito, access_token: str, predicate, timeout: float = 15.0, interval: float = 1.0) -> dict:
    """SetUserMFAPreference/AdminSetUserMFAPreference's effect on GetUserAuthFactors can lag
    briefly on real AWS, so this polls a bounded window instead of trusting the first read."""
    deadline = time.time() + timeout
    factors = cognito.get_user_auth_factors(AccessToken=access_token)
    while not predicate(factors):
        if time.time() >= deadline:
            raise AssertionError(f"GetUserAuthFactors did not converge within {timeout}s: {factors}")
        time.sleep(interval)
        factors = cognito.get_user_auth_factors(AccessToken=access_token)
    return factors


def _totp(secret_b32: str, digits: int = 6, interval: int = 30) -> str:
    """RFC 6238 TOTP, implemented from stdlib primitives only."""
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, "sha1").digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
