"""admin-get-nonexistent-device-fails."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "admin-get-nonexistent-device-fails"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

_PASSWORD = "TestPassw0rd!23"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminGetDevice for a device key never registered to the user answers
    ResourceNotFoundException "Device does not exist.", while the same call for the user's
    registered device returns it."""
    idp = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = _create_confirmed_user(ctx, pool_id)

    # Ground truth: the user has zero registered devices.
    devices = idp.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    assert devices == [], f"expected no devices for a fresh user, got {devices}"

    # Positive control: register a real device, and confirm AdminGetDevice finds it.
    real_device_key = _register_device(ctx, idp, pool_id, client_id, username)
    got = idp.admin_get_device(DeviceKey=real_device_key, UserPoolId=pool_id, Username=username)["Device"]
    assert got["DeviceKey"] == real_device_key, (
        f"expected AdminGetDevice to find the registered device {real_device_key}, got {got['DeviceKey']}"
    )

    fake_device_key = f"{ctx.region}_00000000-0000-0000-0000-000000000abc"
    code, message = _error(
        lambda: idp.admin_get_device(DeviceKey=fake_device_key, UserPoolId=pool_id, Username=username)
    )
    assert (code, message) == ("ResourceNotFoundException", "Device does not exist."), f"expected ResourceNotFoundException, got {(code, message)!r}"


def _create_pool_and_client(ctx) -> tuple[str, str]:
    idp = ctx.client("cognito-idp")
    # Device tracking must be explicitly enabled on the user pool, otherwise every device
    # API (including AdminGetDevice/AdminListDevices) rejects with
    # InvalidUserPoolConfigurationException regardless of whether the device exists.
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: idp.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return pool_id, client_id


def _create_confirmed_user(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    username = ctx.unique_name("sim2real-behav-user-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=_PASSWORD, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)
    ctx.on_cleanup(lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username))
    return username


def _register_device(ctx, idp, pool_id: str, client_id: str, username: str) -> str:
    """Sign the user in to obtain NewDeviceMetadata, then ConfirmDevice it so the device
    is a real, queryable record rather than a name AdminGetDevice has never heard of."""
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )["AuthenticationResult"]
    new_device = auth.get("NewDeviceMetadata")
    assert new_device is not None, "expected NewDeviceMetadata on first sign-in with device tracking enabled"
    device_key = new_device["DeviceKey"]

    # ConfirmDevice requires a DeviceSecretVerifierConfig ("Invalid device credentials given"
    # otherwise); PasswordVerifier/Salt are decoded as signed big-endian integers, so the top bit
    # of the random bytes is cleared to keep them positive.
    idp.confirm_device(
        AccessToken=auth["AccessToken"],
        DeviceKey=device_key,
        DeviceSecretVerifierConfig={
            "PasswordVerifier": _random_nonnegative_b64(64),
            "Salt": _random_nonnegative_b64(16),
        },
    )
    return device_key


def _random_nonnegative_b64(n_bytes: int) -> str:
    data = bytearray(os.urandom(n_bytes))
    data[0] &= 0x7F
    return base64.b64encode(bytes(data)).decode("ascii")


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
