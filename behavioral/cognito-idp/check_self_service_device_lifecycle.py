"""self-service-device-lifecycle."""
from __future__ import annotations

import base64
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "self-service-device-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfirmDevice registers a device visible in ListDevices/GetDevice; ForgetDevice removes it."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-behav-user-")
    _admin_create_confirmed_user(ctx, pool_id, username)

    auth = _admin_password_auth(cognito, pool_id, client_id, username)
    access_token = auth["AccessToken"]
    new_device = auth.get("NewDeviceMetadata")
    assert new_device is not None, "expected NewDeviceMetadata on first sign-in with device tracking enabled"
    device_key = new_device["DeviceKey"]

    confirm_resp = cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="sim2real-device",
        # Real AWS rejects ConfirmDevice with "Invalid device credentials given" unless a
        # DeviceSecretVerifierConfig (opaque SRP-style verifier/salt) is supplied; the service
        # stores these for future device-SRP challenges but doesn't validate the contents here.
        # It does, however, decode PasswordVerifier/Salt as big-endian two's-complement big
        # integers, so a random byte string whose top bit is set is rejected as negative.
        DeviceSecretVerifierConfig={
            "PasswordVerifier": _random_nonnegative_b64(64),
            "Salt": _random_nonnegative_b64(16),
        },
    )
    assert confirm_resp["UserConfirmationNecessary"] is True, (
        f"expected UserConfirmationNecessary=True on first ConfirmDevice under "
        f"DeviceOnlyRememberedOnUserPrompt, got {confirm_resp.get('UserConfirmationNecessary')!r}"
    )

    # With DeviceOnlyRememberedOnUserPrompt enabled, ConfirmDevice's UserConfirmationNecessary=True
    # means the device isn't actually tracked (and won't show up in ListDevices/GetDevice) until
    # the user-prompt step completes, i.e. UpdateDeviceStatus marks it "remembered".
    cognito.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered"
    )

    # ListDevices can briefly lag behind a just-remembered device on real AWS; poll for it.
    device_keys = _poll_until_device_listed(cognito, access_token, device_key)
    assert device_key in device_keys, (
        f"expected {device_key} in ListDevices after marking it remembered, got {device_keys}"
    )

    got = cognito.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert got["DeviceKey"] == device_key, f"expected GetDevice to return {device_key}, got {got['DeviceKey']}"

    # Setting DeviceRememberedStatus back to "not_remembered" removes the device from the
    # caller's own ListDevices view entirely (self-service ListDevices only surfaces devices the
    # pool currently trusts), rather than merely flipping a status field on an otherwise-still-
    # listed entry. Poll (bounded) for that removal before exercising ForgetDevice.
    cognito.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="not_remembered"
    )
    device_keys_unremembered = _poll_until_device_unlisted(cognito, access_token, device_key)
    assert device_key not in device_keys_unremembered, (
        f"expected {device_key} to drop out of ListDevices once not_remembered, "
        f"got {device_keys_unremembered}"
    )

    cognito.forget_device(AccessToken=access_token, DeviceKey=device_key)

    device_keys_after = {d["DeviceKey"] for d in cognito.list_devices(AccessToken=access_token)["Devices"]}
    assert device_key not in device_keys_after, (
        f"expected {device_key} absent from ListDevices after ForgetDevice, got {device_keys_after}"
    )

    code, message = _error(lambda: cognito.get_device(AccessToken=access_token, DeviceKey=device_key))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "Device does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": True},
        UserPoolTags={"sim2real:managed": "true", "sim2real:check": CHECK},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _admin_create_confirmed_user(ctx, pool_id: str, username: str) -> None:
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}, {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _admin_password_auth(cognito, pool_id: str, client_id: str, username: str) -> dict:
    resp = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _random_nonnegative_b64(n_bytes: int) -> str:
    """Random bytes, base64-encoded, guaranteed to decode as a non-negative big integer.

    Real AWS parses DeviceSecretVerifierConfig's PasswordVerifier/Salt as big-endian
    two's-complement integers and rejects the request if the top bit of the first byte
    is set (interpreted as negative), even though it never validates the SRP contents.
    """
    data = bytearray(os.urandom(n_bytes))
    data[0] &= 0x7F
    return base64.b64encode(bytes(data)).decode("ascii")


def _poll_until_device_listed(cognito, access_token: str, device_key: str, timeout: float = 15.0, interval: float = 1.0) -> set:
    deadline = time.time() + timeout
    device_keys: set = set()
    while time.time() < deadline:
        device_keys = {d["DeviceKey"] for d in cognito.list_devices(AccessToken=access_token)["Devices"]}
        if device_key in device_keys:
            return device_keys
        time.sleep(interval)
    raise AssertionError(
        f"device {device_key} did not appear in ListDevices within {timeout}s of being "
        f"marked remembered; last seen: {device_keys}"
    )


def _poll_until_device_unlisted(cognito, access_token: str, device_key: str, timeout: float = 15.0, interval: float = 1.0) -> set:
    deadline = time.time() + timeout
    device_keys: set = set()
    while time.time() < deadline:
        device_keys = {d["DeviceKey"] for d in cognito.list_devices(AccessToken=access_token)["Devices"]}
        if device_key not in device_keys:
            return device_keys
        time.sleep(interval)
    raise AssertionError(
        f"device {device_key} still in ListDevices {timeout}s after being marked "
        f"not_remembered; last seen: {device_keys}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
