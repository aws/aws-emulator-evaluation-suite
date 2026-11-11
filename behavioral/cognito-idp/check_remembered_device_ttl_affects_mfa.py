"""remembered-device-ttl-affects-mfa."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remembered-device-ttl-affects-mfa"
GROUP = 'device-ttl'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"


def _rejection(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _dummy_device_secret_verifier_config():
    """A syntactically-valid (not cryptographically real) SRP
    DeviceSecretVerifierConfig for ConfirmDevice. Both values decode server-side
    as big *unsigned* integers, so clear the high bit of the leading byte."""
    import base64
    import os

    def unsigned_random(n):
        b = bytearray(os.urandom(n))
        b[0] &= 0x7F
        return bytes(b)

    return {
        "PasswordVerifier": base64.b64encode(unsigned_random(128)).decode("ascii"),
        "Salt": base64.b64encode(unsigned_random(16)).decode("ascii"),
    }


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A confirmed device is visible to GetDevice/ListDevices; marking it not_remembered makes
    GetDevice 404 and remembered restores it. An invalid DeviceRememberedStatus is rejected."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"], GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )["AuthenticationResult"]
    meta = auth.get("NewDeviceMetadata")
    assert meta and meta.get("DeviceKey"), (
        f"expected NewDeviceMetadata.DeviceKey on login, got keys={list(auth.keys())}"
    )
    device_key = meta["DeviceKey"]
    access_token = auth["AccessToken"]

    confirm = c.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig=_dummy_device_secret_verifier_config(),
    )
    assert "UserConfirmationNecessary" in confirm, confirm

    # Positive control with the same access token, so the later rejection is about status.
    got_early = c.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert got_early["DeviceKey"] == device_key, got_early

    listed = c.list_devices(AccessToken=access_token)["Devices"]
    assert any(d.get("DeviceKey") == device_key for d in listed), (
        f"device {device_key} missing from ListDevices: {listed}"
    )

    c.update_device_status(AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered")
    c.update_device_status(AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="not_remembered")

    code, message = _rejection(lambda: c.get_device(AccessToken=access_token, DeviceKey=device_key))
    assert code == "ResourceNotFoundException", (
        f"expected GetDevice to reject a device marked not_remembered "
        f"with ResourceNotFoundException, got {code}"
    )
    assert message == "Device does not exist.", f"expected message 'Device does not exist.', got {message!r}"

    # The rejection tracks live status, not a one-way teardown of the device record.
    c.update_device_status(AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="remembered")
    got_restored = c.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert got_restored["DeviceKey"] == device_key, got_restored

    bad_code, bad_message = _rejection(
        lambda: c.update_device_status(
            AccessToken=access_token, DeviceKey=device_key, DeviceRememberedStatus="not_a_real_status"
        )
    )
    assert bad_code == "InvalidParameterException", (
        f"expected the invalid DeviceRememberedStatus to be rejected, got {bad_code}"
    )
    expected_bad = (
        "1 validation error detected: Value 'not_a_real_status' at 'deviceRememberedStatus' "
        "failed to satisfy constraint: Member must satisfy enum value set: [remembered, not_remembered]"
    )
    assert bad_message == expected_bad, f"expected message {expected_bad!r}, got {bad_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
