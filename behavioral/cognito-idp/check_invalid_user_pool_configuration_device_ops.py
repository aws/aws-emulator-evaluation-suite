"""invalid-user-pool-configuration-device-ops."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-user-pool-configuration-device-ops"
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
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("real AWS rejects this call, but it SUCCEEDED")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Without DeviceConfiguration, the four Admin*Device ops fail with
    InvalidUserPoolConfigurationException; once tracking is enabled, AdminListDevices succeeds
    and the unknown-device calls fail with ResourceNotFoundException instead."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="Temp0rar1Pass!",
        MessageAction="SUPPRESS",
        UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}],
    )
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password="Str0ngPassw0rd!", Permanent=True
    )

    fake_device_key = f"{ctx.region}_{uuid.uuid4()}"

    code1, message1 = _error(lambda: c.admin_list_devices(UserPoolId=pool_id, Username=username))
    assert code1 == "InvalidUserPoolConfigurationException", (
        f"AdminListDevices: expected InvalidUserPoolConfigurationException, got {code1}"
    )
    expected_message1 = "Device tracking not currently enabled for this pool."
    assert message1 == expected_message1, (
        f"expected message {expected_message1!r}, got {message1!r}"
    )

    code2, message2 = _error(
        lambda: c.admin_get_device(
            UserPoolId=pool_id, Username=username, DeviceKey=fake_device_key
        )
    )
    assert code2 == "InvalidUserPoolConfigurationException", (
        f"AdminGetDevice: expected InvalidUserPoolConfigurationException, got {code2}"
    )
    expected_message2 = "Device tracking not currently enabled for this pool."
    assert message2 == expected_message2, (
        f"expected message {expected_message2!r}, got {message2!r}"
    )

    code3, message3 = _error(
        lambda: c.admin_update_device_status(
            UserPoolId=pool_id,
            Username=username,
            DeviceKey=fake_device_key,
            DeviceRememberedStatus="remembered",
        )
    )
    assert code3 == "InvalidUserPoolConfigurationException", (
        f"AdminUpdateDeviceStatus: expected InvalidUserPoolConfigurationException, got {code3}"
    )
    expected_message3 = "Device tracking not currently enabled for this pool."
    assert message3 == expected_message3, (
        f"expected message {expected_message3!r}, got {message3!r}"
    )

    code4, message4 = _error(
        lambda: c.admin_forget_device(
            UserPoolId=pool_id, Username=username, DeviceKey=fake_device_key
        )
    )
    assert code4 == "InvalidUserPoolConfigurationException", (
        f"AdminForgetDevice: expected InvalidUserPoolConfigurationException, got {code4}"
    )
    expected_message4 = "Device tracking not currently enabled for this pool."
    assert message4 == expected_message4, (
        f"expected message {expected_message4!r}, got {message4!r}"
    )

    c.update_user_pool(
        UserPoolId=pool_id,
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )

    devices = c.admin_list_devices(UserPoolId=pool_id, Username=username)["Devices"]
    assert devices == [], (
        f"AdminListDevices: expected it to succeed with zero devices once tracking "
        f"is on, got {devices}"
    )

    code5, message5 = _error(
        lambda: c.admin_get_device(
            UserPoolId=pool_id, Username=username, DeviceKey=fake_device_key
        )
    )
    assert code5 == "ResourceNotFoundException", (
        f"AdminGetDevice: expected ResourceNotFoundException once tracking is on, got {code5}"
    )
    expected_message5 = "Device does not exist."
    assert message5 == expected_message5, (
        f"expected message {expected_message5!r}, got {message5!r}"
    )

    code6, message6 = _error(
        lambda: c.admin_update_device_status(
            UserPoolId=pool_id,
            Username=username,
            DeviceKey=fake_device_key,
            DeviceRememberedStatus="remembered",
        )
    )
    assert code6 == "ResourceNotFoundException", (
        f"AdminUpdateDeviceStatus: expected ResourceNotFoundException once tracking is on, got {code6}"
    )
    expected_message6 = "Device does not exist."
    assert message6 == expected_message6, (
        f"expected message {expected_message6!r}, got {message6!r}"
    )

    code7, message7 = _error(
        lambda: c.admin_forget_device(
            UserPoolId=pool_id, Username=username, DeviceKey=fake_device_key
        )
    )
    assert code7 == "ResourceNotFoundException", (
        f"AdminForgetDevice: expected ResourceNotFoundException once tracking is on, got {code7}"
    )
    expected_message7 = "Device does not exist."
    assert message7 == expected_message7, (
        f"expected message {expected_message7!r}, got {message7!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
