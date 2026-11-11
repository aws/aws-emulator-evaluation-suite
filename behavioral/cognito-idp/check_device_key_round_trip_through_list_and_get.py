"""device-key-round-trip-through-list-and-get."""
from __future__ import annotations

import base64
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-key-round-trip-through-list-and-get"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real-Str0ng!Passw0rd"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The DeviceKey from NewDeviceMetadata, once confirmed, is returned unchanged by GetDevice and
    ListDevices; after ForgetDevice, GetDevice fails with ResourceNotFoundException, since still
    returning a forgotten device would be overly permissive."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-devpool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]

    def _delete_pool_with_retry() -> None:
        # Account-level throttling can turn a legitimate DeleteUserPool into
        # TooManyRequestsException right after the burst of admin/auth calls this check
        # makes; retry that one code so cleanup doesn't leak the pool.
        for attempt in range(3):
            try:
                idp.delete_user_pool(UserPoolId=pool_id)
                return
            except ClientError as e:
                if e.response["Error"]["Code"] == "TooManyRequestsException" and attempt < 2:
                    time.sleep(5.0)
                    continue
                raise

    ctx.on_cleanup(_delete_pool_with_retry)

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-devclient-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-devuser-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)

    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    result = auth["AuthenticationResult"]
    access_token = result["AccessToken"]
    new_device = result["NewDeviceMetadata"]
    device_key = new_device["DeviceKey"]
    assert device_key, "AdminInitiateAuth returned no DeviceKey in NewDeviceMetadata"

    # ConfirmDevice requires a DeviceSecretVerifierConfig; the values need not be valid SRP
    # since no device-SRP auth follows. Cognito parses them as signed big-endian integers,
    # so the leading byte's high bit must be clear or it rejects the value as "negative".
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
    forgotten = {"done": False}
    def _cleanup_forget() -> None:
        if not forgotten["done"]:
            idp.forget_device(AccessToken=access_token, DeviceKey=device_key)
    ctx.on_cleanup(_cleanup_forget)

    listed_key = _poll_until(
        probe=lambda: _find_device_key(idp, access_token, device_key),
        predicate=lambda found: found is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert listed_key == device_key, "ListDevices returned a different DeviceKey than ConfirmDevice registered"

    got = idp.get_device(DeviceKey=device_key, AccessToken=access_token)
    assert got["Device"]["DeviceKey"] == device_key, (
        f"GetDevice returned DeviceKey {got['Device'].get('DeviceKey')!r}, expected {device_key!r}"
    )

    # Overly-permissive boundary: once forgotten, the device must not still be gettable,
    # and it must be closed to mutation too, not just to reads.
    idp.forget_device(AccessToken=access_token, DeviceKey=device_key)
    forgotten["done"] = True

    update_code, update_message = _error(
        lambda: idp.update_device_status(
            AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"UpdateDeviceStatus on a forgotten device: expected ResourceNotFoundException, got {update_code!r}"
    )
    assert update_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {update_message!r}"
    )

    code, message = _error(lambda: idp.get_device(DeviceKey=device_key, AccessToken=access_token))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _find_device_key(idp, access_token: str, device_key: str) -> str | None:
    resp = idp.list_devices(AccessToken=access_token, Limit=60)
    for device in resp.get("Devices", []):
        if device.get("DeviceKey") == device_key:
            return device["DeviceKey"]
    return None


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
