"""get-device-bogus-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-device-bogus-key-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetDevice/ForgetDevice for a device key never registered for the caller are rejected
    rather than returning or forgetting a phantom device."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        AutoVerifiedAttributes=["email"],
        # Without device tracking every device API fails with
        # InvalidUserPoolConfigurationException, whether or not the device exists.
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    client_id = c.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda: c.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    password = "Str0ngPassw0rd!"
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    auth = c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]
    access_token = auth["AccessToken"]

    # Ground truth: device tracking is live and this caller has zero registered devices --
    # distinguishes "this specific key is bogus" from "device ops are universally rejected".
    devices = c.list_devices(AccessToken=access_token)["Devices"]
    assert devices == [], f"expected no devices for a fresh user, got {devices}"

    bogus_device_key = f"{ctx.region}_00000000-0000-4000-8000-000000000000"
    code1, message1 = _error(
        lambda: c.get_device(AccessToken=access_token, DeviceKey=bogus_device_key)
    )
    assert code1 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unregistered device, got {code1}"
    )
    expected1 = "Device does not exist."
    assert message1 == expected1, f"expected message {expected1!r}, got {message1!r}"

    code2, message2 = _error(
        lambda: c.forget_device(AccessToken=access_token, DeviceKey=bogus_device_key)
    )
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for an unregistered device, got {code2}"
    )
    expected2 = "Device does not exist."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
