"""list-devices-reflects-only-remembered-devices-for-user."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-devices-reflects-only-remembered-devices-for-user"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListDevices for a user returns exactly that user's own confirmed devices, never a
    device confirmed by a different user in the same pool."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool_with_device_tracking(ctx)
    client_id = _create_password_client(ctx, pool_id)

    user_a = ctx.unique_name("sim2real-usera-")
    user_b = ctx.unique_name("sim2real-userb-")
    _create_confirmed_user(ctx, pool_id, user_a)
    _create_confirmed_user(ctx, pool_id, user_b)

    auth_a = _sign_in(ctx, client_id, user_a)
    auth_b = _sign_in(ctx, client_id, user_b)
    device_key_a = auth_a["NewDeviceMetadata"]["DeviceKey"]
    device_key_b = auth_b["NewDeviceMetadata"]["DeviceKey"]
    assert device_key_a != device_key_b, (
        f"expected distinct device keys for two independent sign-ins, both got {device_key_a!r}"
    )

    cognito.confirm_device(
        AccessToken=auth_a["AccessToken"], DeviceKey=device_key_a, DeviceSecretVerifierConfig=_verifier_config()
    )
    cognito.confirm_device(
        AccessToken=auth_b["AccessToken"], DeviceKey=device_key_b, DeviceSecretVerifierConfig=_verifier_config()
    )

    devices_a = cognito.list_devices(AccessToken=auth_a["AccessToken"])["Devices"]
    devices_b = cognito.list_devices(AccessToken=auth_b["AccessToken"])["Devices"]

    keys_a = {d["DeviceKey"] for d in devices_a}
    keys_b = {d["DeviceKey"] for d in devices_b}

    assert keys_a == {device_key_a}, f"expected user A's ListDevices == {{{device_key_a!r}}}, got {keys_a!r}"
    assert keys_b == {device_key_b}, f"expected user B's ListDevices == {{{device_key_b!r}}}, got {keys_b!r}"
    assert device_key_b not in keys_a, (
        f"user B's device {device_key_b!r} leaked into user A's ListDevices {keys_a!r}"
    )
    assert device_key_a not in keys_b, (
        f"user A's device {device_key_a!r} leaked into user B's ListDevices {keys_b!r}"
    )


def _create_pool_with_device_tracking(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-pool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_password_client(ctx, pool_id):
    cognito = ctx.client("cognito-idp")
    resp = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )
    return resp["UserPoolClient"]["ClientId"]


def _create_confirmed_user(ctx, pool_id, username):
    cognito = ctx.client("cognito-idp")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        MessageAction="SUPPRESS",
        TemporaryPassword=_PASSWORD,
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True)


def _sign_in(ctx, client_id, username):
    cognito = ctx.client("cognito-idp")
    resp = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    return resp["AuthenticationResult"]


def _verifier_config():
    import base64
    import os

    def _positive(n):
        buf = bytearray(os.urandom(n))
        buf[0] &= 0x7F
        return base64.b64encode(bytes(buf)).decode()

    return {
        "PasswordVerifier": _positive(128),
        "Salt": _positive(16),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
