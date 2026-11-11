"""self-service-list-devices-reflects-confirmed-device."""
from __future__ import annotations

import base64
import hashlib
import os

from behavioral_harness import tags

CHECK = "self-service-list-devices-reflects-confirmed-device"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

# ConfirmDevice requires a real SRP verifier/salt pair (device-SRP registration half);
# see https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-device-tracking.html
_N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B2"
    "2514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7E"
    "C6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45"
    "B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F3562085"
    "52BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180"
    "E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898"
    "FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF"
)
_BIG_N = int(_N_HEX, 16)
_G = 2
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _pad_hex(value) -> str:
    hash_str = format(value, "x") if isinstance(value, int) else value
    if len(hash_str) % 2 == 1:
        hash_str = "0" + hash_str
    elif hash_str[0] in "89ABCDEFabcdef":
        hash_str = "00" + hash_str
    return hash_str


def _hex_hash(hex_string: str) -> str:
    return hashlib.sha256(bytearray.fromhex(hex_string)).hexdigest().zfill(64)


def _rand_long(nbytes: int) -> int:
    return int.from_bytes(os.urandom(nbytes), "big")


def _generate_device_verifier(device_group_key: str, device_key: str):
    device_password = base64.standard_b64encode(os.urandom(40)).decode()
    combined = f"{device_group_key}{device_key}:{device_password}".encode()
    combined_hash = hashlib.sha256(combined).hexdigest().zfill(64)
    salt_hex = _pad_hex(_rand_long(16))
    x_value = int(_hex_hash(salt_hex + combined_hash), 16)
    verifier_hex = _pad_hex(pow(_G, x_value, _BIG_N))
    verifier_config = {
        "PasswordVerifier": base64.standard_b64encode(bytes.fromhex(verifier_hex)).decode(),
        "Salt": base64.standard_b64encode(bytes.fromhex(salt_hex)).decode(),
    }
    return device_password, verifier_config


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After ConfirmDevice, the self-service ListDevices call (using the user's own
    access token) enumerates that device."""
    cognito = ctx.client("cognito-idp")
    pool_id, client_id = _create_pool_and_client(ctx)
    username = ctx.unique_name("sim2real-user-")
    password = "Perm@nent1234"
    access_token, device_key, device_group_key = _create_user_and_sign_in(ctx, pool_id, client_id, username, password)
    _, verifier_config = _generate_device_verifier(device_group_key, device_key)

    cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig=verifier_config,
    )

    devices = cognito.list_devices(AccessToken=access_token)["Devices"]
    keys = [d["DeviceKey"] for d in devices]
    assert device_key in keys, f"confirmed device {device_key} missing from ListDevices: {keys}"
    assert len(devices) == 1


def _create_pool_and_client(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags=_POOL_TAGS,
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
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    return pool_id, client_id


def _create_user_and_sign_in(ctx, pool_id, client_id, username, password):
    cognito = ctx.client("cognito-idp")
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
    device_key = auth["NewDeviceMetadata"]["DeviceKey"]
    device_group_key = auth["NewDeviceMetadata"]["DeviceGroupKey"]
    return access_token, device_key, device_group_key


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
