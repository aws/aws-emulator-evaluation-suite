"""admin-set-user-mfa-preference-concurrent-conflicting-writes-last-write-wins."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "admin-set-user-mfa-preference-concurrent-conflicting-writes-last-write-wins"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


def _totp(secret_base32: str, *, digits: int = 6, step: int = 30) -> str:
    """RFC 6238 TOTP code for an AssociateSoftwareToken base32 secret (stdlib-only)."""
    key = base64.b32decode(secret_base32.upper() + "=" * ((8 - len(secret_base32) % 8) % 8))
    counter = int(time.time()) // step
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    truncated = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10 ** digits)).zfill(digits)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Racing AdminSetUserMFAPreference enable+prefer and disable writes settle on one stable
    state: GetUserAuthFactors never reports enabled without the preference, or disabled with it."""
    cognito = ctx.client("cognito-idp")

    pool_id = _create_user_pool(ctx)
    client_id = _create_public_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-behav-mfauser-")
    password = "Sim2Real-Behav-Pw1!"

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    # No MFA method is enabled yet at sign-in time, so this returns tokens directly
    # with no challenge.
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # AdminSetUserMFAPreference only toggles an existing TOTP factor, so register one first.
    secret_code = cognito.associate_software_token(AccessToken=access_token)["SecretCode"]
    user_code = _totp(secret_code)
    cognito.verify_software_token(
        AccessToken=access_token, UserCode=user_code, FriendlyDeviceName="sim2real-behav"
    )

    def read_state():
        factors = cognito.get_user_auth_factors(AccessToken=access_token)
        enabled = "SOFTWARE_TOKEN_MFA" in factors.get("UserMFASettingList", [])
        preferred = factors.get("PreferredMfaSetting")
        return enabled, preferred

    def enable_and_prefer():
        cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": True},
        )

    def disable():
        cognito.admin_set_user_mfa_preference(
            UserPoolId=pool_id,
            Username=username,
            SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
        )

    # Apply each write serially first: otherwise a no-op write would pass as the disabled outcome.
    enable_and_prefer()
    got_enabled, got_preferred = read_state()
    assert got_enabled is True and got_preferred == "SOFTWARE_TOKEN_MFA", (
        f"admin_set_user_mfa_preference(Enabled=True) did not take effect in isolation: "
        f"enabled={got_enabled!r} preferred={got_preferred!r}"
    )
    disable()
    got_enabled, got_preferred = read_state()
    assert got_enabled is False and got_preferred in (None, ""), (
        f"admin_set_user_mfa_preference(Enabled=False) did not take effect in isolation: "
        f"enabled={got_enabled!r} preferred={got_preferred!r}"
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_enable = pool.submit(enable_and_prefer)
        fut_disable = pool.submit(disable)
        fut_enable.result()
        fut_disable.result()

    enabled, preferred = read_state()
    if enabled:
        assert preferred == "SOFTWARE_TOKEN_MFA", (
            f"software token MFA reports enabled but PreferredMfaSetting is "
            f"{preferred!r} -- a torn intermediate state between the two racing writes"
        )
    else:
        assert preferred in (None, ""), (
            f"software token MFA was disabled by the race but PreferredMfaSetting is "
            f"still {preferred!r} -- a torn intermediate state between the two racing "
            "writes"
        )

    for _ in range(3):
        time.sleep(0.5)
        actual = read_state()
        assert actual == (enabled, preferred), (
            f"state flapped after settling: expected {(enabled, preferred)!r}, got {actual!r}"
        )


def _create_user_pool(ctx) -> str:
    cognito = ctx.client("cognito-idp")
    # MfaConfiguration="OPTIONAL" on CreateUserPool trips an SMS/auto-verify validation;
    # SetUserPoolMfaConfig enables software-token MFA afterward without that requirement.
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-mfapool-"),
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    return pool_id


def _create_public_client(ctx, pool_id: str) -> str:
    cognito = ctx.client("cognito-idp")
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-mfaclient-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(
        lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)
    )
    return client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
