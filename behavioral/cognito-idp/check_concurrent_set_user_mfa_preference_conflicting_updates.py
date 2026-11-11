"""concurrent-set-user-mfa-preference-conflicting-updates."""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-set-user-mfa-preference-conflicting-updates"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent SetUserMFAPreference calls that both enable software-token MFA but disagree on
    PreferredMfa leave it enabled with one of the two preferences, GetUser and GetUserAuthFactors
    agree on it, and repeated reads do not change."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx, cognito)
    access_token = _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id)

    assoc = cognito.associate_software_token(AccessToken=access_token)
    secret = assoc["SecretCode"]
    _verify_totp_with_retry(cognito, access_token, secret)

    def _set(preferred: bool):
        return cognito.set_user_mfa_preference(
            AccessToken=access_token,
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": preferred},
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_true = pool.submit(_set, True)
        fut_false = pool.submit(_set, False)
        fut_true.result()
        fut_false.result()

    user = cognito.get_user(AccessToken=access_token)
    settings_list = user.get("UserMFASettingList", [])
    preferred = user.get("PreferredMfaSetting")

    assert "SOFTWARE_TOKEN_MFA" in settings_list, (
        f"both racing writes set Enabled=True, but SOFTWARE_TOKEN_MFA is missing from "
        f"UserMFASettingList={settings_list} -- lost update"
    )
    assert preferred in (None, "SOFTWARE_TOKEN_MFA"), (
        f"PreferredMfaSetting={preferred!r} is neither of the two racing outcomes -- corrupted state"
    )

    # GetUserAuthFactors reads the same record through a different operation; it must report
    # the same settled outcome as GetUser.
    factors = cognito.get_user_auth_factors(AccessToken=access_token)
    factors_settings = factors.get("UserMFASettingList", [])
    factors_preferred = factors.get("PreferredMfaSetting")
    assert factors_preferred == preferred, (
        f"GetUser reports PreferredMfaSetting={preferred!r} but the independent "
        f"GetUserAuthFactors reports {factors_preferred!r} -- the two read paths disagree "
        "about which racing write settled"
    )
    assert ("SOFTWARE_TOKEN_MFA" in factors_settings) == ("SOFTWARE_TOKEN_MFA" in settings_list), (
        f"GetUser UserMFASettingList={settings_list} and GetUserAuthFactors "
        f"UserMFASettingList={factors_settings} disagree on whether SOFTWARE_TOKEN_MFA is enabled"
    )

    # Freeze detector: once the race has settled, repeated independent reads must keep reporting the
    # identical outcome, never flap between the two candidate final states.
    for _ in range(3):
        time.sleep(0.5)
        again = cognito.get_user(AccessToken=access_token)
        again_settings = again.get("UserMFASettingList", [])
        again_preferred = again.get("PreferredMfaSetting")
        assert again_settings == settings_list and again_preferred == preferred, (
            f"state flapped after settling: was UserMFASettingList={settings_list} "
            f"PreferredMfaSetting={preferred!r}, now UserMFASettingList={again_settings} "
            f"PreferredMfaSetting={again_preferred!r}"
        )


def _totp(secret_b32: str, for_time: float, digits: int = 6, interval: int = 30) -> str:
    padded = secret_b32.upper() + "=" * ((8 - len(secret_b32) % 8) % 8)
    key = base64.b32decode(padded)
    counter = int(for_time // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code).zfill(digits)


def _verify_totp_with_retry(cognito, access_token: str, secret: str) -> None:
    last_exc = None
    for attempt in range(3):
        code = _totp(secret, time.time() + attempt * 30)
        try:
            resp = cognito.verify_software_token(AccessToken=access_token, UserCode=code)
            if resp.get("Status") == "SUCCESS":
                return
        except Exception as exc:  # CodeMismatchException on clock-skew boundary
            last_exc = exc
            time.sleep(1)
    raise AssertionError(f"could not verify software token after retries: {last_exc}")


def _create_pool_and_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-mfapool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    # Software-token MFA must be enabled at the pool level before any user can
    # AssociateSoftwareToken (otherwise SoftwareTokenMFANotFoundException).
    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-mfaclient-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user_and_sign_in(ctx, cognito, pool_id, client_id) -> str:
    username = ctx.unique_name("sim2real-behav-mfauser-")
    password = "Sim2Real!Behav0r123"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]["AccessToken"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
