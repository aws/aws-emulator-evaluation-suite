"""deep-cognito-idp-2-token-rotation-device-key-omitted-rejected."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-cognito-idp-2-token-rotation-device-key-omitted-rejected"
GROUP = "refresh-token-rotation"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """In a device-remembering pool, GetTokensFromRefreshToken without DeviceKey is refused with
    NotAuthorizedException, registers no new device, and does not spend the token, which then
    rotates with the confirmed DeviceKey without adding a device."""
    c = ctx.client("cognito-idp")

    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-rot-pool-"),
        UserPoolTags={"sim2real": CHECK},
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-rot-g0-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH"],
        RefreshTokenRotation={"Feature": "ENABLED", "RetryGracePeriodSeconds": 0},
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-rot-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    signin = c.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    ndm = signin.get("NewDeviceMetadata") or {}
    device_key = ndm.get("DeviceKey")
    assert device_key, f"device-tracking pool issued no NewDeviceMetadata on sign-in: {ndm!r}"

    confirmed = c.confirm_device(
        AccessToken=signin["AccessToken"], DeviceKey=device_key, DeviceName="sim2real-behav-device",
        DeviceSecretVerifierConfig={"PasswordVerifier": _positive_b64(64), "Salt": _positive_b64(16)},
    )
    ctx.on_cleanup(lambda: c.admin_forget_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key))
    assert confirmed.get("UserConfirmationNecessary") is False, f"ConfirmDevice returned {confirmed!r}"

    before = _device_keys(c, pool_id, username)
    assert device_key in before, f"confirmed device {device_key!r} missing from AdminListDevices {before!r}"

    # AWS refuses here, although the API docs say a missing device key gets a new device issued.
    code, message = _error(lambda: c.get_tokens_from_refresh_token(
        ClientId=client_id, RefreshToken=signin["RefreshToken"]))
    assert code == "NotAuthorizedException", (
        f"GetTokensFromRefreshToken without DeviceKey returned {code!r} ({message!r}), expected NotAuthorizedException"
    )
    expected_message = "Invalid Refresh Token."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_refused = _device_keys(c, pool_id, username)
    assert after_refused == before, (
        f"refused refresh changed the device list {sorted(before)!r} -> {sorted(after_refused)!r}"
    )

    # Positive control: the token was not spent; with the confirmed key it rotates.
    redeemed = c.get_tokens_from_refresh_token(
        ClientId=client_id, RefreshToken=signin["RefreshToken"], DeviceKey=device_key,
    )["AuthenticationResult"]
    assert redeemed.get("RefreshToken") and redeemed["RefreshToken"] != signin["RefreshToken"], (
        f"redemption with DeviceKey did not rotate; keys {sorted(redeemed)!r}"
    )
    assert not redeemed.get("NewDeviceMetadata"), (
        f"redemption with a confirmed DeviceKey minted a new device: {redeemed.get('NewDeviceMetadata')!r}"
    )
    after_ok = _device_keys(c, pool_id, username)
    assert after_ok == before, f"redemption with DeviceKey changed the device list to {sorted(after_ok)!r}"



def _positive_b64(n: int) -> str:
    """Random bytes whose leading byte has the high bit clear: Cognito parses the verifier and
    salt as signed big integers and rejects a negative one."""
    raw = bytearray(os.urandom(n))
    raw[0] = (raw[0] & 0x7F) | 0x01
    return base64.b64encode(bytes(raw)).decode()


def _device_keys(c, pool_id: str, username: str) -> set[str]:
    keys, token = set(), None
    while True:
        kw = {"UserPoolId": pool_id, "Username": username, "Limit": 60}
        if token:
            kw["PaginationToken"] = token
        page = c.admin_list_devices(**kw)
        keys.update(d["DeviceKey"] for d in page.get("Devices", []))
        token = page.get("PaginationToken")
        if not token:
            return keys


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        out = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    keys = sorted((out or {}).get("AuthenticationResult", out or {}))
    raise AssertionError(f"call expected to fail SUCCEEDED (response keys {keys!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
