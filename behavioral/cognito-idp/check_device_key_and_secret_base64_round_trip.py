"""device-key-and-secret-base64-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "device-key-and-secret-base64-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The device key confirmed via ConfirmDevice, and its unicode device_name attribute, round-trip via GetDevice.
    Also asserts GetDevice rejects a well-formed but never-confirmed device key (overly-permissive guard)."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-device-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-device"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-device-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-device-user-")
    password = "Sim2Real-Behav!9x"
    cognito.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]
    new_device_metadata = auth["AuthenticationResult"]["NewDeviceMetadata"]
    device_key = new_device_metadata["DeviceKey"]
    assert device_key, "no NewDeviceMetadata.DeviceKey returned even though DeviceConfiguration is set"

    device_name = "\u65e5\u672c\u8a9e-\u2764\ufe0f-D\u00e9vice-\u0421\u0438\u043c2Real"

    def _positive_b64(n_bytes: int) -> str:
        # Cognito parses PasswordVerifier/Salt as a big-endian signed integer; clear the sign bit on the
        # leading byte so random bytes never fail validation as "negative value for salt or password verifier".
        raw = bytearray(os.urandom(n_bytes))
        raw[0] &= 0x7F
        return base64.b64encode(bytes(raw)).decode("ascii")

    password_verifier = _positive_b64(128)
    salt = _positive_b64(16)

    cognito.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceName=device_name,
        DeviceSecretVerifierConfig={"PasswordVerifier": password_verifier, "Salt": salt},
    )

    device = cognito.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert device["DeviceKey"] == device_key, "DeviceKey was not returned byte-identical by GetDevice"

    attrs = {a["Name"]: a["Value"] for a in device.get("DeviceAttributes", [])}
    assert attrs.get("device_name") == device_name, (
        f"device_name attribute {attrs.get('device_name')!r} does not match the unicode name set via ConfirmDevice"
    )

    # --- overly-permissive guard: a well-formed but never-confirmed device key must be rejected ---
    region = device_key.rsplit("_", 1)[0] if "_" in device_key else pool_id.split("_", 1)[0]
    fake_guid = "".join(reversed(device_key.rsplit("_", 1)[-1])) or "00000000-0000-0000-0000-000000000000"
    bogus_device_key = f"{region}_{fake_guid}"
    assert bogus_device_key != device_key, "constructed bogus device key collided with the real one"
    code, message = _error(
        lambda: cognito.get_device(AccessToken=access_token, DeviceKey=bogus_device_key)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unconfirmed device key, got {code!r}"
    )
    assert message == "Device does not exist.", (
        f"expected the exact ResourceNotFoundException message 'Device does not exist.', got {message!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target that accepts a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
