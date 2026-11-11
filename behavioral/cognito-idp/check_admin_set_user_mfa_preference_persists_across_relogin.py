"""admin-set-user-mfa-preference-persists-across-relogin."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-persists-across-relogin"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An MFA preference set via AdminSetUserMFAPreference survives AdminUserGlobalSignOut
    and is still enforced (challenged) on a fresh AdminInitiateAuth."""
    cidp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cidp)
    client_id = _create_client(ctx, cidp, pool_id)

    username = ctx.unique_name("sim2real-mfapersist-")
    password = "Sim2Real-Passw0rd!23"
    cidp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    cidp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth1 = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth1["AuthenticationResult"]["AccessToken"]
    assert "ChallengeName" not in auth1, "sign-in should complete without a challenge before MFA is enabled"

    assoc = cidp.associate_software_token(AccessToken=access_token)
    secret_code = assoc["SecretCode"]
    verify = _verify_with_clock_tolerance(cidp, access_token, secret_code)
    assert verify["Status"] == "SUCCESS", f"expected VerifySoftwareToken to report SUCCESS, got {verify!r}"

    cidp.admin_set_user_mfa_preference(
        UserPoolId=pool_id,
        Username=username,
        SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
    )

    cidp.admin_user_global_sign_out(UserPoolId=pool_id, Username=username)

    auth2 = cidp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert auth2.get("ChallengeName") == "SOFTWARE_TOKEN_MFA", (
        f"expected the persisted MFA preference to force a SOFTWARE_TOKEN_MFA challenge, "
        f"got ChallengeName={auth2.get('ChallengeName')!r}"
    )
    assert "AuthenticationResult" not in auth2, "sign-in should not complete until the MFA challenge is answered"


def _create_user_pool(ctx, cidp) -> str:
    resp = cidp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-mfapersist"},
    )
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cidp.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before any user's access token
    # can call AssociateSoftwareToken (otherwise SoftwareTokenMFANotFoundException).
    cidp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    return pool_id


def _create_client(ctx, cidp, pool_id: str) -> str:
    resp = cidp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )
    return resp["UserPoolClient"]["ClientId"]


def _totp(secret_b32: str, digits: int = 6, interval: int = 30, offset_steps: int = 0) -> str:
    padding = "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(secret_b32.upper() + padding)
    counter = int(time.time() // interval) + offset_steps
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10**digits)).zfill(digits)


def _verify_with_clock_tolerance(cidp, access_token: str, secret_code: str) -> dict:
    """VerifySoftwareToken enforces a tight TOTP window; try the neighbouring 30s steps too
    so a small clock delta between this host and Cognito doesn't flake the check."""
    last_error = None
    for offset_steps in (0, -1, 1, -2, 2):
        code = _totp(secret_code, offset_steps=offset_steps)
        try:
            return cidp.verify_software_token(AccessToken=access_token, UserCode=code)
        except cidp.exceptions.CodeMismatchException as exc:
            last_error = exc
    raise AssertionError(f"VerifySoftwareToken never accepted a TOTP code within +/-2 steps: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
