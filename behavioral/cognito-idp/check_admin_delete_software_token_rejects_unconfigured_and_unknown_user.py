"""admin-delete-software-token-rejects-unconfigured-and-unknown-user."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-delete-software-token-rejects-unconfigured-and-unknown-user"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_NOT_CONFIGURED = (
    "ResourceNotFoundException",
    "Software token MFA has not been configured for this user.",
)
_UNKNOWN_USER = ("UserNotFoundException", "User does not exist.")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminDeleteSoftwareToken rejects a user with no TOTP factor and a username that
    doesn't exist, each with its own code and message; a user who did enroll TOTP has
    the factor actually removed by the identical call."""
    cog = ctx.client("cognito-idp")
    password = "Sim2RealP@ss9142"

    pool_id = cog.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
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
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("totpuser-")
    cog.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(lambda: cog.admin_delete_user(UserPoolId=pool_id, Username=username))
    cog.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    # neighbour 1: the username exists but never associated a software token.
    code, message = _error(lambda: cog.admin_delete_software_token(UserPoolId=pool_id, Username=username))
    assert (code, message) == _NOT_CONFIGURED, (
        f"expected {_NOT_CONFIGURED}, got {(code, message)!r}"
    )

    # neighbour 2: the username never existed at all.
    unknown_username = ctx.unique_name("nouser-")
    code2, message2 = _error(
        lambda: cog.admin_delete_software_token(UserPoolId=pool_id, Username=unknown_username)
    )
    assert (code2, message2) == _UNKNOWN_USER, f"expected {_UNKNOWN_USER}, got {(code2, message2)!r}"

    # positive control: a user who actually enrolled TOTP has the factor removed by the
    # identical call, proving the two rejections above are specific to the missing factor
    # and the missing user, not a blanket refusal of the operation.
    auth = cog.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    secret_code = cog.associate_software_token(AccessToken=access_token)["SecretCode"]

    verified = False
    last_error = None
    for offset in (0, -1, 1, -2, 2):
        try:
            cog.verify_software_token(AccessToken=access_token, UserCode=_totp(secret_code, offset))
            verified = True
            break
        except cog.exceptions.CodeMismatchException as exc:  # wrong 30s time window, try next offset
            last_error = exc
    assert verified, f"VerifySoftwareToken never succeeded: {last_error}"

    factors_before = cog.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN" in factors_before["ConfiguredUserAuthFactors"], (
        f"positive control: expected SOFTWARE_TOKEN after enrollment, got "
        f"{factors_before['ConfiguredUserAuthFactors']}"
    )

    cog.admin_delete_software_token(UserPoolId=pool_id, Username=username)

    factors_after = cog.admin_get_user_auth_factors(UserPoolId=pool_id, Username=username)
    assert "SOFTWARE_TOKEN" not in factors_after["ConfiguredUserAuthFactors"], (
        f"expected SOFTWARE_TOKEN gone after AdminDeleteSoftwareToken, got "
        f"{factors_after['ConfiguredUserAuthFactors']}"
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
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code_int:06d}"


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
