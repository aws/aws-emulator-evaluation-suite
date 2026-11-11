"""get-device-reflects-confirmed-device-attributes."""
from __future__ import annotations

import base64
import os
import time

from behavioral_harness import tags

CHECK = "get-device-reflects-confirmed-device-attributes"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-user-"}


def _positive_bytes(n: int) -> bytes:
    # Cognito parses PasswordVerifier/Salt as signed big-endian integers, so the
    # leading byte's high bit must be clear or it rejects the value as "negative".
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
    """GetDevice returns device attributes (device name) and a recent
    last-authenticated timestamp exactly as established at ConfirmDevice time."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(
        ctx, DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False}
    )
    client_id = _create_client(ctx, pool_id)
    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real!Passw0rd"
    _create_confirmed_user(ctx, pool_id, username, password)

    start = time.time()
    auth = _admin_password_auth(ctx, pool_id, client_id, username, password)
    access_token = auth["AccessToken"]
    device_key = auth["NewDeviceMetadata"]["DeviceKey"]
    device_name = ctx.unique_name("my-device-")

    confirm = idp.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName=device_name,
        DeviceSecretVerifierConfig=_device_verifier_config(),
    )
    assert confirm["UserConfirmationNecessary"] is False, (
        f"ConfirmDevice reported UserConfirmationNecessary={confirm['UserConfirmationNecessary']!r}, expected False"
    )

    device = idp.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    end = time.time()
    assert device["DeviceKey"] == device_key, f"GetDevice DeviceKey {device['DeviceKey']!r} != {device_key!r}"

    attrs = {a["Name"]: a["Value"] for a in device.get("DeviceAttributes", [])}
    assert attrs.get("device_name") == device_name, (
        f"DeviceAttributes device_name {attrs.get('device_name')!r} != confirmed name {device_name!r}"
    )

    # Two-sided: a stubbed sentinel (e.g. epoch zero) fails the lower bound, a
    # nonsensical future value fails the upper bound. Skew allows clock drift.
    skew = 60.0
    last_auth = device["DeviceLastAuthenticatedDate"].timestamp()
    created = device["DeviceCreateDate"].timestamp()
    assert start - skew <= last_auth <= end + skew, (
        f"DeviceLastAuthenticatedDate {last_auth} not within [{start - skew}, {end + skew}]"
    )
    assert start - skew <= created <= end + skew, (
        f"DeviceCreateDate {created} not within [{start - skew}, {end + skew}]"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    resp = idp.create_user_pool(PoolName=name, UserPoolTags=_TAGS, **kwargs)
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
