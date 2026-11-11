"""device-remember-status-ttl-persists."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-remember-status-ttl-persists"
GROUP = "visibility-timeout-ttl"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A confirmed device marked "remembered" via UpdateDeviceStatus persists across repeated
    GetDevice reads (no short-lived expiry), and ForgetDevice removes it so GetDevice and
    further mutations fail."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        # Device tracking must be explicitly enabled at the pool level for auth
        # responses to carry NewDeviceMetadata (which ConfirmDevice requires).
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": True},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: _ignore(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id)))

    username, password = _create_confirmed_user(ctx, pool_id)

    auth = idp.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    new_device = auth["AuthenticationResult"].get("NewDeviceMetadata")
    assert new_device is not None, "expected NewDeviceMetadata on first sign-in with device tracking enabled"
    device_key = new_device["DeviceKey"]

    # ConfirmDevice rejects with "Invalid device credentials given" unless a
    # DeviceSecretVerifierConfig is supplied; its contents are not validated, but a value
    # whose top bit is set decodes as a negative integer and is rejected.
    idp.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName="sim2real-device",
        DeviceSecretVerifierConfig={
            "PasswordVerifier": _random_nonnegative_b64(64),
            "Salt": _random_nonnegative_b64(16),
        },
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.forget_device(AccessToken=access_token, DeviceKey=device_key)))

    idp.update_device_status(
        AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered",
    )

    for attempt in range(3):
        got = idp.get_device(AccessToken=access_token, DeviceKey=device_key)
        assert got["Device"]["DeviceKey"] == device_key, (
            f"read {attempt}: expected persisted device {device_key!r}, got {got['Device'].get('DeviceKey')!r}"
        )

    listed = idp.list_devices(AccessToken=access_token)
    assert any(d["DeviceKey"] == device_key for d in listed.get("Devices", [])), (
        "confirmed device missing from ListDevices while still remembered"
    )

    idp.forget_device(AccessToken=access_token, DeviceKey=device_key)

    code, message = _error(lambda: idp.get_device(AccessToken=access_token, DeviceKey=device_key))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a forgotten device, got {code!r}"
    )
    assert message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {message!r}"
    )

    listed_after = idp.list_devices(AccessToken=access_token).get("Devices", [])
    assert not any(d["DeviceKey"] == device_key for d in listed_after), (
        f"forgotten device {device_key} still present in ListDevices: {listed_after}"
    )

    # The forgotten device id is not just unreadable but unusable: a mutation
    # against it must fail the same way a read does, not silently no-op.
    mutate_code, mutate_message = _error(
        lambda: idp.update_device_status(
            AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered",
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException mutating a forgotten device, got {mutate_code!r}"
    )
    assert mutate_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {mutate_message!r}"
    )


def _random_nonnegative_b64(n_bytes: int) -> str:
    """Random bytes, base64-encoded, that decode as a non-negative big-endian integer."""
    data = bytearray(os.urandom(n_bytes))
    data[0] &= 0x7F
    return base64.b64encode(bytes(data)).decode("ascii")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ResourceNotFoundException",
            "UserNotFoundException",
        ):
            raise


def _create_confirmed_user(ctx, pool_id):
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username,
        TemporaryPassword="Temp0rary!Passw0rd", MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: _ignore(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
