"""software-token-mfa-enrollment-lifecycle."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "software-token-mfa-enrollment-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateSoftwareToken + VerifySoftwareToken enable TOTP MFA; AdminDeleteSoftwareToken removes it."""
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

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    # Software token MFA must be turned on at the pool level before a user can associate one;
    # real AWS rejects AssociateSoftwareToken with SoftwareTokenMFANotFoundException otherwise.
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    before = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN_MFA" not in before.get("UserMFASettingList", []), (
        f"expected no SOFTWARE_TOKEN_MFA before enrollment, got {before.get('UserMFASettingList')}"
    )

    secret = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    assert secret, "expected AssociateSoftwareToken to return a non-empty SecretCode"

    status = _verify_with_retry(cognito, access_token, secret)
    assert status == "SUCCESS", status

    # VerifySoftwareToken registers the token but real AWS doesn't activate it as a usable MFA
    # factor (reflected in UserMFASettingList) until the user (or an admin) explicitly opts in
    # with SetUserMFAPreference.
    cognito.set_user_mfa_preference(
        AccessToken=access_token,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    # VerifySoftwareToken enables the factor, but real AWS can take a moment before
    # AdminGetUser's UserMFASettingList reflects it; poll for the terminal state.
    after = _poll_until_mfa_setting(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username),
        lambda u: "SOFTWARE_TOKEN_MFA" in u.get("UserMFASettingList", []),
    )
    assert "SOFTWARE_TOKEN_MFA" in after.get("UserMFASettingList", []), after.get("UserMFASettingList")

    cognito.admin_delete_software_token(UserPoolId=pool_id, Username=username)

    final = _poll_until_mfa_setting(
        lambda: cognito.admin_get_user(UserPoolId=pool_id, Username=username),
        lambda u: "SOFTWARE_TOKEN_MFA" not in u.get("UserMFASettingList", []),
    )
    assert "SOFTWARE_TOKEN_MFA" not in final.get("UserMFASettingList", []), final.get("UserMFASettingList")


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


def _poll_until_mfa_setting(fetch, predicate, timeout: float = 15.0, interval: float = 1.0) -> dict:
    deadline = time.time() + timeout
    last = fetch()
    while time.time() < deadline:
        if predicate(last):
            return last
        time.sleep(interval)
        last = fetch()
    raise AssertionError(
        f"MFA setting never reached the expected state within {timeout}s; "
        f"last observed UserMFASettingList={last.get('UserMFASettingList')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
