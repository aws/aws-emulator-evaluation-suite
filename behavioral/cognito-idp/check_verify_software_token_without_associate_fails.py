"""verify-software-token-without-associate-fails."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from typing import Any

from behavioral_harness import tags

CHECK = "verify-software-token-without-associate-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """VerifySoftwareToken called on an access token that never ran AssociateSoftwareToken
    fails, rather than succeeding; the same access token DOES succeed once a software
    token has actually been associated and the correct TOTP code is supplied."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username, password = _create_confirmed_user(ctx, pool_id)
    access_token = _admin_access_token(ctx, pool_id, client_id, username, password)

    # Real AWS requires software-token MFA to be enabled on the user pool before
    # AssociateSoftwareToken (and thus VerifySoftwareToken) can be used at all;
    # without this, AssociateSoftwareToken itself fails with
    # SoftwareTokenMFANotFoundException, which would invalidate the positive control
    # below. Enable it here so the only variable under test is whether
    # AssociateSoftwareToken was ever called for this user/session.
    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )

    # Negative: no AssociateSoftwareToken was ever called for this user/session. Real AWS
    # rejects with SoftwareTokenMFANotFoundException because there is no registered TOTP
    # factor to verify against (EnableSoftwareTokenMFAException/NotAuthorizedException are
    # not what the service actually returns for this case).
    code, message = _error(lambda: idp.verify_software_token(AccessToken=access_token, UserCode="123456"))
    assert code == "SoftwareTokenMFANotFoundException", (
        f"expected SoftwareTokenMFANotFoundException, got {code}"
    )
    expected = "Software Token MFA does not exist for the user."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: associate a real software token, compute the correct TOTP code,
    # and confirm VerifySoftwareToken now succeeds against the same access token.
    associate_resp = idp.associate_software_token(AccessToken=access_token)
    secret = associate_resp["SecretCode"]

    verify_resp = None
    last_error = None
    for offset in (0, -1, 1):
        user_code = _totp(secret, for_time=time.time() + offset * 30)
        try:
            verify_resp = idp.verify_software_token(AccessToken=access_token, UserCode=user_code)
            break
        except Exception as exc:  # noqa: BLE001 - retry across clock-skew windows only
            last_error = exc
    assert verify_resp is not None, f"TOTP verification never succeeded across skew windows: {last_error}"
    assert verify_resp["Status"] == "SUCCESS", f"expected SUCCESS, got {verify_resp['Status']}"

    # Terminal read is independent of the mutating VerifySoftwareToken call: confirm the
    # factor is now actually registered for this user via a separate read operation, not
    # just the mutating call's own response.
    factors = idp.get_user_auth_factors(AccessToken=access_token)
    assert "SOFTWARE_TOKEN" in factors.get("ConfiguredUserAuthFactors", []), (
        f"expected SOFTWARE_TOKEN in ConfiguredUserAuthFactors after a successful verify, "
        f"got {factors.get('ConfiguredUserAuthFactors')}"
    )


def _totp(secret_b32: str, for_time: float, interval: int = 30, digits: int = 6) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8))
    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    resp = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    client_id = resp["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


def _create_confirmed_user(ctx, pool_id: str) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-behav-user-")
    password = "TestPassw0rd!23"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    return username, password


def _admin_access_token(ctx, pool_id: str, client_id: str, username: str, password: str) -> str:
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]["AccessToken"]


def _error(fn) -> tuple[Any, Any]:
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because a
    target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
