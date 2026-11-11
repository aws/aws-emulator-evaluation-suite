"""admin-device-lifecycle."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-device-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_PASSWORD = "S1mParity!Behave2024"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminGetDevice/AdminListDevices mirror status; AdminUpdateDeviceStatus + AdminForgetDevice work."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-behav-user-")
    _admin_create_confirmed_user(ctx, pool_id, username)

    auth = _admin_password_auth(cognito, pool_id, client_id, username)
    access_token = auth["AccessToken"]
    new_device = auth.get("NewDeviceMetadata")
    assert new_device is not None, "expected NewDeviceMetadata on first sign-in with device tracking enabled"
    device_key = new_device["DeviceKey"]

    # Register the device via the self-service API, then drive it through the admin surface.
    # Real AWS rejects ConfirmDevice with "Invalid device credentials given" unless a
    # DeviceSecretVerifierConfig (opaque SRP-style verifier/salt) is supplied; the service stores
    # these for future device-SRP challenges but doesn't validate their cryptographic contents here.
    # It does, however, decode PasswordVerifier/Salt as big-endian two's-complement big integers,
    # so a random byte string whose top bit happens to be set is rejected as negative; clear it.
    cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig={
            "PasswordVerifier": _random_nonnegative_b64(64),
            "Salt": _random_nonnegative_b64(16),
        },
    )

    got = cognito.admin_get_device(DeviceKey=device_key, UserPoolId=pool_id, Username=username)["Device"]
    assert got["DeviceKey"] == device_key, f"expected AdminGetDevice to return {device_key}, got {got['DeviceKey']}"

    device_keys = {
        d["DeviceKey"]
        for d in cognito.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    }
    assert device_key in device_keys, f"expected {device_key} in AdminListDevices, got {device_keys}"

    cognito.admin_update_device_status(
        UserPoolId=pool_id, Username=username, DeviceKey=device_key, DeviceRememberedStatus="remembered"
    )
    cognito.admin_update_device_status(
        UserPoolId=pool_id, Username=username, DeviceKey=device_key, DeviceRememberedStatus="not_remembered"
    )

    cognito.admin_forget_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key)

    device_keys_after = {
        d["DeviceKey"]
        for d in cognito.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    }
    assert device_key not in device_keys_after, f"expected {device_key} gone from AdminListDevices, got {device_keys_after}"

    code, message = _error(
        lambda: cognito.admin_get_device(DeviceKey=device_key, UserPoolId=pool_id, Username=username)
    )
    assert (code, message) == ("ResourceNotFoundException", "Device does not exist."), f"expected ResourceNotFoundException, got {(code, message)!r}"

    # The forgotten device is not just absent from reads; it is unusable as a mutation target too.
    code, message = _error(
        lambda: cognito.admin_update_device_status(
            UserPoolId=pool_id, Username=username, DeviceKey=device_key, DeviceRememberedStatus="remembered"
        )
    )
    assert (code, message) == ("ResourceNotFoundException", "Device does not exist."), f"expected ResourceNotFoundException on a forgotten device, got {(code, message)!r}"


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": True},
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


def _random_nonnegative_b64(n_bytes: int) -> str:
    """Random bytes, base64-encoded, guaranteed to decode as a non-negative big integer.

    Real AWS parses DeviceSecretVerifierConfig's PasswordVerifier/Salt as big-endian
    two's-complement integers and rejects the request if the top bit of the first byte
    is set (interpreted as negative), even though it never validates the SRP contents.
    """
    data = bytearray(os.urandom(n_bytes))
    data[0] &= 0x7F
    return base64.b64encode(bytes(data)).decode("ascii")


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
