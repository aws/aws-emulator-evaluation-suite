"""list-devices-empty-when-no-devices-confirmed."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "list-devices-empty-when-no-devices-confirmed"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDevices for a signed-in user who never confirmed a device returns an empty list, and after
    ConfirmDevice returns exactly that device key."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    password = "Perm@nent1234"

    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass!234",
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    auth = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    response = cognito.list_devices(AccessToken=access_token)
    assert response["Devices"] == [], f"expected no devices before confirmation, got {response['Devices']}"

    device_key = auth["NewDeviceMetadata"]["DeviceKey"]
    cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName=ctx.unique_name("sim2real-device-"),
        DeviceSecretVerifierConfig=_device_verifier_config(),
    )
    ctx.on_cleanup(lambda: cognito.forget_device(AccessToken=access_token, DeviceKey=device_key))

    after = cognito.list_devices(AccessToken=access_token)["Devices"]
    assert [d["DeviceKey"] for d in after] == [device_key], (
        f"expected exactly the just-confirmed device {device_key!r}, got {after!r}"
    )


def _positive_bytes(n: int) -> bytes:
    raw = bytearray(os.urandom(n))
    raw[0] &= 0x7F
    return bytes(raw)


def _device_verifier_config():
    return {
        "PasswordVerifier": base64.b64encode(_positive_bytes(128)).decode("ascii"),
        "Salt": base64.b64encode(_positive_bytes(16)).decode("ascii"),
    }


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 8,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
