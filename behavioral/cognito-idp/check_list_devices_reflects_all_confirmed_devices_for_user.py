"""list-devices-reflects-all-confirmed-devices-for-user."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "list-devices-reflects-all-confirmed-devices-for-user"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


def _positive_bytes(n: int) -> bytes:
    raw = bytearray(os.urandom(n))
    raw[0] &= 0x7F
    return bytes(raw)


def _device_verifier_config():
    return {
        "PasswordVerifier": base64.b64encode(_positive_bytes(128)).decode("ascii"),
        "Salt": base64.b64encode(_positive_bytes(16)).decode("ascii"),
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDevices returns exactly the set of devices confirmed for the
    authenticated user, matching count and device keys precisely."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(
        ctx, DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False}
    )
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    _create_confirmed_user(ctx, pool_id, username, password)

    # Three separate sign-ins with no DEVICE_KEY supplied each mint a fresh device key.
    auth1 = _admin_password_auth(ctx, pool_id, client_id, username, password)
    auth2 = _admin_password_auth(ctx, pool_id, client_id, username, password)
    auth3 = _admin_password_auth(ctx, pool_id, client_id, username, password)

    device_key_1 = auth1["NewDeviceMetadata"]["DeviceKey"]
    device_key_2 = auth2["NewDeviceMetadata"]["DeviceKey"]
    device_key_3 = auth3["NewDeviceMetadata"]["DeviceKey"]
    assert len({device_key_1, device_key_2, device_key_3}) == 3, (
        f"expected three distinct device keys, got {device_key_1!r}, {device_key_2!r}, {device_key_3!r}"
    )

    idp.confirm_device(
        AccessToken=auth1["AccessToken"],
        DeviceKey=device_key_1,
        DeviceName="device-one",
        DeviceSecretVerifierConfig=_device_verifier_config(),
    )
    idp.confirm_device(
        AccessToken=auth2["AccessToken"],
        DeviceKey=device_key_2,
        DeviceName="device-two",
        DeviceSecretVerifierConfig=_device_verifier_config(),
    )
    # device_key_3 is deliberately left unconfirmed: it is the negative control that
    # proves ListDevices reflects CONFIRMED devices, not every device key ever minted.
    # No per-device forget_device teardown: deleting the pool (registered in
    # _create_user_pool) already removes every device along with it.

    listed = idp.list_devices(AccessToken=auth2["AccessToken"], Limit=20)["Devices"]
    listed_keys = {d["DeviceKey"] for d in listed}

    assert len(listed) == 2, f"expected exactly 2 confirmed devices listed, got {len(listed)}: {listed_keys}"
    assert listed_keys == {device_key_1, device_key_2}, (
        f"expected listed device keys {{{device_key_1!r}, {device_key_2!r}}}, got {listed_keys!r}"
    )
    assert device_key_3 not in listed_keys, (
        f"unconfirmed device {device_key_3!r} must not appear in ListDevices, got {listed_keys!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    kwargs.setdefault(
        "UserPoolTags", {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool-"}
    )
    resp = idp.create_user_pool(PoolName=name, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, pool_id, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-client-")
    kwargs.setdefault("ExplicitAuthFlows", ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"])
    resp = idp.create_user_pool_client(UserPoolId=pool_id, ClientName=name, GenerateSecret=False, **kwargs)
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username, password, user_attributes=None):
    idp = ctx.client("cognito-idp")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=password,
        UserAttributes=user_attributes or [],
    )
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)


def _admin_password_auth(ctx, pool_id, client_id, username, password):
    idp = ctx.client("cognito-idp")
    resp = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return resp["AuthenticationResult"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
