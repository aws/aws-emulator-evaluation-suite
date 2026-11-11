"""list-devices-pagination-stable-order."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "list-devices-pagination-stable-order"
GROUP = "ordering"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDevices returns confirmed devices in a stable order: paginating through
    Limit=2 pages twice independently yields the identical device-key sequence, and
    that sequence matches a single unpaginated listing."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx, cognito)
    username, password = _create_confirmed_user(ctx, cognito, pool_id)
    access_token = _sign_in(cognito, client_id, username, password)["AccessToken"]

    device_keys = []
    for _ in range(5):
        device_key = _sign_in_and_get_device_key(cognito, client_id, username, password)
        cognito.confirm_device(
            AccessToken=access_token,
            DeviceKey=device_key,
            DeviceName=f"dev-{device_key[-8:]}",
            DeviceSecretVerifierConfig=_new_verifier_config(),
        )
        device_keys.append(device_key)

    full_order = _list_all_devices(cognito, access_token, page_limit=60)
    assert sorted(full_order) == sorted(device_keys), (
        f"expected all {len(device_keys)} confirmed devices in ListDevices, got {full_order}"
    )

    order_a = _list_all_devices(cognito, access_token, page_limit=2)
    order_b = _list_all_devices(cognito, access_token, page_limit=2)

    assert order_a == full_order, f"paginated order {order_a} != unpaginated order {full_order}"
    assert order_b == full_order, f"second paginated pass {order_b} != unpaginated order {full_order}"
    assert order_a == order_b, "two independent paginated ListDevices passes disagreed on order"


def _sign_in(cognito, client_id, username, password) -> dict:
    auth = cognito.initiate_auth(
        AuthFlow="USER_PASSWORD_AUTH",
        ClientId=client_id,
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    return auth["AuthenticationResult"]


def _sign_in_and_get_device_key(cognito, client_id, username, password) -> str:
    # Each fresh USER_PASSWORD_AUTH sign-in (no prior DeviceKey supplied) is treated
    # as an unrecognized device and gets its own server-issued NewDeviceMetadata --
    # DeviceKey is never client-generated, so ConfirmDevice rejects fabricated ones.
    result = _sign_in(cognito, client_id, username, password)
    metadata = result.get("NewDeviceMetadata")
    assert metadata and metadata.get("DeviceKey"), (
        f"sign-in did not return NewDeviceMetadata; is device tracking enabled on the pool? {result}"
    )
    return metadata["DeviceKey"]


def _new_verifier_config() -> dict:
    # SRP fields aren't cryptographically validated at ConfirmDevice time (they're
    # only exercised on a later device-SRP auth challenge) -- any well-formed,
    # non-negative (top bit clear) base64 blobs satisfy the API's parameter
    # validation, which parses them as big-endian signed integers.
    verifier = bytearray(os.urandom(128))
    verifier[0] &= 0x7F
    salt = bytearray(os.urandom(16))
    salt[0] &= 0x7F
    return {
        "PasswordVerifier": base64.b64encode(bytes(verifier)).decode("ascii"),
        "Salt": base64.b64encode(bytes(salt)).decode("ascii"),
    }



def _create_pool_and_client(ctx, cognito):
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-devpool-"),
        UserPoolTags=_TAGS,
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-devclient-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_confirmed_user(ctx, cognito, pool_id) -> tuple[str, str]:
    username = ctx.unique_name("sim2real-behav-devuser-")
    password = "Sim2Real!Behav0r123"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password



def _list_all_devices(cognito, access_token: str, *, page_limit: int) -> list[str]:
    keys: list[str] = []
    pagination_token = None
    while True:
        kwargs = {"AccessToken": access_token, "Limit": page_limit}
        if pagination_token:
            kwargs["PaginationToken"] = pagination_token
        resp = cognito.list_devices(**kwargs)
        keys.extend(d["DeviceKey"] for d in resp.get("Devices", []))
        pagination_token = resp.get("PaginationToken")
        if not pagination_token:
            break
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
