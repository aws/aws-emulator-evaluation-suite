"""device-lifecycle-admin."""
from __future__ import annotations

import base64
import os

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "device-lifecycle-admin"
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


def _dummy_device_secret_verifier_config() -> dict:
    """A syntactically valid (not cryptographically real) DeviceSecretVerifierConfig.
    Both values are decoded server-side as big integers, so the leading byte's high bit
    is masked off."""
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
    """AdminGetDevice, AdminUpdateDeviceStatus, AdminListDevices and AdminForgetDevice mirror
    the self-service device lifecycle on the same device record (created via ConfirmDevice,
    which has no admin equivalent)."""
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

    c.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig=_dummy_device_secret_verifier_config(),
    )

    got = c.admin_get_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key)["Device"]
    assert got["DeviceKey"] == device_key, got["DeviceKey"]
    modified_before = got["DeviceLastModifiedDate"]

    c.admin_update_device_status(
        UserPoolId=pool_id,
        Username=username,
        DeviceKey=device_key,
        DeviceRememberedStatus="remembered",
    )

    # DeviceType has no remembered-status field (write-only via AdminUpdateDeviceStatus), so
    # the only proof this call was not a no-op is that the device's last-modified timestamp
    # advanced.
    got_after_status = c.admin_get_device(
        UserPoolId=pool_id, Username=username, DeviceKey=device_key
    )["Device"]
    assert got_after_status["DeviceLastModifiedDate"] > modified_before, (
        f"AdminUpdateDeviceStatus did not advance DeviceLastModifiedDate: "
        f"before={modified_before}, after={got_after_status['DeviceLastModifiedDate']}"
    )

    listed = c.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    assert any(d["DeviceKey"] == device_key for d in listed), (
        f"device {device_key} missing from AdminListDevices: {listed}"
    )

    c.admin_forget_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key)

    listed2 = c.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    assert not any(d["DeviceKey"] == device_key for d in listed2), (
        f"forgotten device {device_key} still present in AdminListDevices: {listed2}"
    )
    code, message = _error(
        lambda: c.admin_get_device(UserPoolId=pool_id, Username=username, DeviceKey=device_key)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a forgotten device, got {code}"
    )
    assert message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {message!r}"
    )

    # Gone means unusable, not just unreadable: a mutation aimed at the same dead device
    # key must also fail, rather than silently recreating or no-oping it.
    mutate_code, mutate_message = _error(
        lambda: c.admin_update_device_status(
            UserPoolId=pool_id,
            Username=username,
            DeviceKey=device_key,
            DeviceRememberedStatus="not_remembered",
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException updating a forgotten device, got {mutate_code}"
    )
    assert mutate_message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {mutate_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
