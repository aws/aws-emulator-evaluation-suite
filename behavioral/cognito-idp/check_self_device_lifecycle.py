"""self-device-lifecycle."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "self-device-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A device confirmed and remembered appears in GetDevice and ListDevices, leaves ListDevices while
    not_remembered and returns when remembered again; after ForgetDevice it is unlisted and GetDevice
    and UpdateDeviceStatus fail with ResourceNotFoundException and "Device does not exist."."""
    idp = ctx.client("cognito-idp")

    pool_id, client_id = _create_pool_with_device_tracking(ctx)
    username = ctx.unique_name("sim2real-selfdev-user-")
    password = "Sim2Real-Pw!23456"
    _create_confirmed_user(ctx, pool_id, username, password)

    auth = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]
    device_key = auth["NewDeviceMetadata"]["DeviceKey"]

    confirm_result = idp.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="self-lifecycle-device",
        DeviceSecretVerifierConfig=_fake_verifier_config(),
    )
    # DeviceOnlyRememberedOnUserPrompt=True means ConfirmDevice alone can never remember the
    # device -- the pool always defers to the user prompt, so UserConfirmationNecessary is
    # always True under this configuration, never a value ConfirmDevice decided on its own.
    assert confirm_result["UserConfirmationNecessary"] is True, (
        f"expected UserConfirmationNecessary=True under DeviceOnlyRememberedOnUserPrompt=True, "
        f"got {confirm_result.get('UserConfirmationNecessary')!r}"
    )

    # With DeviceOnlyRememberedOnUserPrompt=True, ConfirmDevice alone leaves the device in a
    # tentative state that the pool does not yet expose via GetDevice/ListDevices: the user
    # must explicitly decide whether to remember it (UpdateDeviceStatus) before the device is
    # committed as a queryable resource. Make that decision immediately, then poll (bounded,
    # to tolerate any residual propagation delay) rather than assuming instant visibility.
    idp.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
    )
    got = _poll_until(
        lambda: idp.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"],
        lambda d: d["DeviceKey"] == device_key,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert got["DeviceKey"] == device_key, f"expected {device_key}, got {got.get('DeviceKey')!r}"

    listed = idp.list_devices(AccessToken=access_token)["Devices"]
    assert any(d["DeviceKey"] == device_key for d in listed), (
        f"device {device_key} missing from ListDevices: {[d.get('DeviceKey') for d in listed]}"
    )

    # On real Cognito, setting DeviceRememberedStatus back to "not_remembered" removes the
    # device from the caller's own ListDevices view entirely (self-service ListDevices only
    # surfaces devices the pool currently trusts to bypass MFA), rather than merely flipping
    # a status field on an otherwise-still-listed entry. Poll (bounded) for that removal, then
    # toggle back to "remembered" as a positive control showing the transition is reversible
    # before exercising ForgetDevice.
    idp.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="not_remembered"
    )
    _poll_until(
        lambda: idp.list_devices(AccessToken=access_token)["Devices"],
        lambda devices: all(d["DeviceKey"] != device_key for d in devices),
        timeout_s=30.0,
        interval_s=2.0,
    )

    idp.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
    )
    _poll_until(
        lambda: idp.list_devices(AccessToken=access_token)["Devices"],
        lambda devices: any(d["DeviceKey"] == device_key for d in devices),
        timeout_s=30.0,
        interval_s=2.0,
    )

    idp.forget_device(AccessToken=access_token, DeviceKey=device_key)
    get_code, get_message = _rejection(
        lambda: idp.get_device(AccessToken=access_token, DeviceKey=device_key)
    )
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading a forgotten device, got {get_code!r}"
    )
    assert get_message == "Device does not exist.", (
        f"expected message 'Device does not exist.' reading a forgotten device, got {get_message!r}"
    )
    after_forget = idp.list_devices(AccessToken=access_token)["Devices"]
    assert all(d["DeviceKey"] != device_key for d in after_forget), (
        f"forgotten device {device_key} still present in ListDevices: "
        f"{[d.get('DeviceKey') for d in after_forget]}"
    )

    # A mutation on the same dead device key must fail the same way a read does -- the id is
    # not merely absent from listings, it is unusable for any further operation.
    update_code, update_message = _rejection(
        lambda: idp.update_device_status(
            AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a forgotten device, got {update_code!r}"
    )
    assert update_message == "Device does not exist.", (
        f"expected message 'Device does not exist.' mutating a forgotten device, got {update_message!r}"
    )


def _create_pool_with_device_tracking(ctx):
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-selfdev-pool-"),
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": True,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-selfdev-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user(ctx, pool_id, username, password) -> None:
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _fake_verifier_config():
    # AWS parses these fields as big-endian signed BigIntegers; if the top bit of the
    # first byte is set they are read as negative, which the service rejects. Clear it
    # so the random bytes always decode as a non-negative integer.
    def _non_negative_bytes(n):
        data = bytearray(os.urandom(n))
        data[0] &= 0x7F
        return bytes(data)

    return {
        "PasswordVerifier": base64.b64encode(_non_negative_bytes(128)).decode("ascii"),
        "Salt": base64.b64encode(_non_negative_bytes(16)).decode("ascii"),
    }


def _rejection(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            last = probe()
            last_err = None
            if predicate(last):
                return last
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = err
        time.sleep(interval_s)
    if last_err is not None:
        raise last_err
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
