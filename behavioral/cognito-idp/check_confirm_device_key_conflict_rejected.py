"""confirm-device-key-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "confirm-device-key-conflict-rejected"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!Passw0rd"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmDevice rejects a DeviceKey that doesn't belong to the caller's own access token
    (a foreign or already-confirmed key), and the caller's own device list is unaffected by the
    rejected call."""
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

    # Positive control: each user can legitimately confirm their own device.
    cognito.confirm_device(
        AccessToken=auth_a["AccessToken"],
        DeviceKey=device_key_a,
        DeviceSecretVerifierConfig=_verifier_config(),
    )
    cognito.confirm_device(
        AccessToken=auth_b["AccessToken"],
        DeviceKey=device_key_b,
        DeviceSecretVerifierConfig=_verifier_config(),
    )

    # Break exactly one thing: A tries to confirm a device using B's device key. Cognito
    # validates that the DeviceKey belongs to the calling access token's own device
    # namespace, so a foreign key is rejected as an invalid parameter rather than accepted.
    code_cross, message_cross = _error(
        lambda: cognito.confirm_device(
            AccessToken=auth_a["AccessToken"],
            DeviceKey=device_key_b,
            DeviceSecretVerifierConfig=_verifier_config(),
        )
    )
    assert code_cross == "InvalidParameterException", (
        f"expected ConfirmDevice with a foreign DeviceKey to be rejected as "
        f"InvalidParameterException, got {code_cross!r}"
    )
    assert message_cross == "Invalid device key given.", (
        f"expected the exact foreign-device-key refusal message, got {message_cross!r}"
    )

    # Re-confirming the caller's own already-registered device key is also rejected -- a
    # device key can be confirmed exactly once.
    code_self, message_self = _error(
        lambda: cognito.confirm_device(
            AccessToken=auth_a["AccessToken"],
            DeviceKey=device_key_a,
            DeviceSecretVerifierConfig=_verifier_config(),
        )
    )
    assert code_self == "InvalidParameterException", (
        f"expected re-confirming an already-registered DeviceKey to be rejected as "
        f"InvalidParameterException, got {code_self!r}"
    )
    assert message_self == "Invalid device key given.", (
        f"expected the exact re-confirm refusal message, got {message_self!r}"
    )

    # The caller's own device list is unaffected by either rejected call.
    devices_a = {d["DeviceKey"] for d in cognito.list_devices(AccessToken=auth_a["AccessToken"])["Devices"]}
    assert devices_a == {device_key_a}, f"expected only {device_key_a!r} in A's device list, got {devices_a!r}"
    assert device_key_b not in devices_a, f"B's device key {device_key_b!r} leaked into A's device list {devices_a!r}"


def _create_pool_with_device_tracking(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        DeviceConfiguration={"ChallengeRequiredOnNewDevice": False, "DeviceOnlyRememberedOnUserPrompt": False},
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
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


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


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
