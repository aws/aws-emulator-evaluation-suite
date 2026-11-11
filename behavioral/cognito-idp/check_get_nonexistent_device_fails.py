"""get-nonexistent-device-fails."""
from __future__ import annotations

import base64
import os
from typing import Any

from behavioral_harness import tags

CHECK = "get-nonexistent-device-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDevice returns the device the user registered and fails with ResourceNotFoundException and its
    exact message for an unregistered device key."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)
    client_id = _create_client(ctx, pool_id)
    username, password = _create_confirmed_user(ctx, pool_id)
    access_token, device_key = _admin_access_token(ctx, pool_id, client_id, username, password)

    # Ground truth: this caller's own device list is empty.
    devices = idp.list_devices(AccessToken=access_token)["Devices"]
    assert devices == [], f"expected no devices for a fresh user, got {devices}"

    real_device_key = _confirm_device(ctx, idp, access_token, device_key)
    got = idp.get_device(DeviceKey=real_device_key, AccessToken=access_token)["Device"]
    assert got["DeviceKey"] == real_device_key, (
        f"expected GetDevice to return the registered device {real_device_key}, got {got.get('DeviceKey')}"
    )

    fake_device_key = f"{ctx.region}_00000000-0000-0000-0000-0000000000ff"
    code, message = _error(lambda: idp.get_device(DeviceKey=fake_device_key, AccessToken=access_token))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Device does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    # Device tracking must be explicitly enabled on the user pool, otherwise every device
    # API (including ListDevices/GetDevice) rejects with
    # InvalidUserPoolConfigurationException regardless of whether the device exists.
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags=_TAGS,
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


def _admin_access_token(ctx, pool_id: str, client_id: str, username: str, password: str) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    result = resp["AuthenticationResult"]
    return result["AccessToken"], result["NewDeviceMetadata"]["DeviceKey"]


def _confirm_device(ctx, idp, access_token: str, device_key: str) -> str:
    # ConfirmDevice requires a DeviceSecretVerifierConfig (PasswordVerifier + Salt); the
    # values don't need to be cryptographically valid here since we never perform a
    # subsequent device-SRP authentication with them -- we only need the device registered
    # so GetDevice has a real key to succeed on. Cognito parses these as signed big-endian
    # integers, so the leading byte's high bit must be clear or it rejects the value as
    # "negative".
    def _positive_bytes(n: int) -> bytes:
        raw = bytearray(os.urandom(n))
        raw[0] &= 0x7F
        return bytes(raw)

    verifier_config = {
        "PasswordVerifier": base64.b64encode(_positive_bytes(128)).decode("ascii"),
        "Salt": base64.b64encode(_positive_bytes(16)).decode("ascii"),
    }
    idp.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig=verifier_config,
        DeviceName=ctx.unique_name("sim2real-device-"),
    )
    ctx.on_cleanup(lambda: idp.forget_device(AccessToken=access_token, DeviceKey=device_key))
    return device_key


def _error(fn) -> tuple[Any, Any]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
