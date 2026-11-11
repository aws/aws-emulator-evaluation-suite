"""confirm-device-duplicate-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "confirm-device-duplicate-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
PASSWORD = "Str0ngPassw0rd!"


def _err(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _dummy_device_secret_verifier_config():
    """A syntactically-valid (but not cryptographically real) SRP DeviceSecretVerifierConfig for
    ConfirmDevice. ConfirmDevice just stores whatever verifier/salt it's given; both values are
    decoded server-side as big *unsigned* integers, so the high bit of the leading byte must be
    clear (mask it off) or the service rejects them as negative."""
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


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _new_client(ctx, c, pool_id, **kwargs):
    kwargs.setdefault("GenerateSecret", False)
    client = c.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), **kwargs
    )["UserPoolClient"]
    ctx.on_cleanup(
        lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client["ClientId"])
    )
    return client


def _new_confirmed_user(ctx, c, pool_id, password=PASSWORD, **extra_attrs):
    username = ctx.unique_name("sim2real-behav-cip-user-")
    attrs = [{"Name": "email", "Value": f"{username}@example.com"}]
    attrs.extend({"Name": k, "Value": v} for k, v in extra_attrs.items())
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=attrs,
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)
    return username, password


def _login_with_new_device(c, pool_id, client_id, username, password):
    resp = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    auth = resp["AuthenticationResult"]
    meta = auth.get("NewDeviceMetadata")
    assert meta and meta.get("DeviceKey"), (
        f"expected NewDeviceMetadata.DeviceKey on login (pool DeviceConfiguration enabled?), "
        f"got AuthenticationResult keys={list(auth.keys())}"
    )
    return auth, meta["DeviceKey"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ConfirmDevice for a DeviceKey that is already confirmed is refused with
    InvalidParameterException "Invalid device key given.", and the device record keeps its
    DeviceLastModifiedDate and stays the user's only device."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(
        ctx,
        c,
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )
    client_id = _new_client(
        ctx,
        c,
        pool_id,
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["ClientId"]
    username, password = _new_confirmed_user(ctx, c, pool_id)

    auth, device_key = _login_with_new_device(c, pool_id, client_id, username, password)
    access_token = auth["AccessToken"]

    # Positive control: the first confirmation of a fresh device key succeeds outright (an
    # unhandled ClientError here fails the check, establishing that the target isn't simply
    # rejecting every ConfirmDevice call).
    c.confirm_device(
        AccessToken=access_token,
        DeviceKey=device_key,
        DeviceSecretVerifierConfig=_dummy_device_secret_verifier_config(),
    )
    before = c.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert before["DeviceKey"] == device_key, (
        f"expected GetDevice to return the just-confirmed device {device_key!r}, got {before['DeviceKey']!r}"
    )

    code, message = _err(
        lambda: c.confirm_device(
            AccessToken=access_token,
            DeviceKey=device_key,
            DeviceSecretVerifierConfig=_dummy_device_secret_verifier_config(),
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Invalid device key given.", (
        f"expected the exact duplicate-device refusal message, got {message!r}"
    )

    # Effect absent: GetDevice cannot return the verifier/salt, but an overwrite bumps
    # DeviceLastModifiedDate, so an unchanged timestamp shows the record was not touched.
    after = c.get_device(AccessToken=access_token, DeviceKey=device_key)["Device"]
    assert after["DeviceKey"] == device_key, (
        f"expected GetDevice to still return {device_key!r} after the rejected duplicate, got {after['DeviceKey']!r}"
    )
    assert after["DeviceLastModifiedDate"] == before["DeviceLastModifiedDate"], (
        f"rejected duplicate ConfirmDevice must not modify the device record, "
        f"got DeviceLastModifiedDate {before['DeviceLastModifiedDate']!r} -> {after['DeviceLastModifiedDate']!r}"
    )

    listed = {d["DeviceKey"] for d in c.list_devices(AccessToken=access_token)["Devices"]}
    assert listed == {device_key}, f"expected exactly the one confirmed device, got {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
