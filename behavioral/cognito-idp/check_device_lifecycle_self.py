"""device-lifecycle-self."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-lifecycle-self"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)


def _dummy_device_secret_verifier_config() -> dict:
    """A syntactically-valid (but not cryptographically real) SRP
    DeviceSecretVerifierConfig for ConfirmDevice. Both values are decoded
    server-side as big *unsigned* integers, so the high bit of the leading
    byte must be clear (mask it off) or the service rejects them as negative."""
    def unsigned_random(n: int) -> bytes:
        b = bytearray(os.urandom(n))
        b[0] &= 0x7F
        return bytes(b)

    return {
        "PasswordVerifier": base64.b64encode(unsigned_random(128)).decode("ascii"),
        "Salt": base64.b64encode(unsigned_random(16)).decode("ascii"),
    }


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A remembered device transitions confirm->get->status-update->list->
    forget, disappearing from list once forgotten (self-service, AccessToken-
    authorized surface)."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    password = "Str0ngPassw0rd!"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    meta = auth.get("NewDeviceMetadata")
    assert meta and meta.get("DeviceKey"), (
        f"expected NewDeviceMetadata.DeviceKey on login, got keys={list(auth.keys())}"
    )
    device_key = meta["DeviceKey"]
    access_token = auth["AccessToken"]

    confirm = c.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="probe-device",
        DeviceSecretVerifierConfig=_dummy_device_secret_verifier_config(),
    )
    # DeviceOnlyRememberedOnUserPrompt=False means the pool commits the device as
    # remembered at ConfirmDevice time itself, with no separate user-prompt step needed.
    assert confirm["UserConfirmationNecessary"] is False, confirm

    got = c.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert got["DeviceKey"] == device_key, got["DeviceKey"]

    # Prove UpdateDeviceStatus actually drives the caller's own ListDevices view, not just
    # that the device happens to be visible already: drop it, confirm it disappears, then
    # bring it back before exercising ForgetDevice.
    c.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="not_remembered"
    )
    listed_unremembered = _poll_until(
        lambda: c.list_devices(AccessToken=access_token)["Devices"],
        lambda devices: not any(d["DeviceKey"] == device_key for d in devices),
    )
    assert not any(d["DeviceKey"] == device_key for d in listed_unremembered), (
        f"device {device_key} still in ListDevices after DeviceRememberedStatus=not_remembered: "
        f"{listed_unremembered}"
    )

    c.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
    )
    listed = _poll_until(
        lambda: c.list_devices(AccessToken=access_token)["Devices"],
        lambda devices: any(d["DeviceKey"] == device_key for d in devices),
    )
    assert any(d["DeviceKey"] == device_key for d in listed), (
        f"device {device_key} missing from ListDevices: {listed}"
    )

    c.forget_device(AccessToken=access_token, DeviceKey=device_key)

    listed2 = c.list_devices(AccessToken=access_token)["Devices"]
    assert not any(d["DeviceKey"] == device_key for d in listed2), (
        f"forgotten device {device_key} still present in ListDevices: {listed2}"
    )
    code, message = _error(lambda: c.get_device(AccessToken=access_token, DeviceKey=device_key))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a forgotten device, got {code}"
    )
    assert message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {message!r}"
    )
    mutate_code, mutate_message = _error(
        lambda: c.update_device_status(
            AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a forgotten device, got {mutate_code}"
    )
    assert mutate_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {mutate_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
