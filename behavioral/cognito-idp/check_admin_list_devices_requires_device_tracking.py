"""admin-list-devices-requires-device-tracking."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-list-devices-requires-device-tracking"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

# A password that satisfies the default Cognito password policy
# (min length 8, upper, lower, number, symbol).
DEFAULT_PASSWORD = "TempPassw0rd!23"


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    """Poll probe() until predicate(result); raise AssertionError on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting; last={last!r}")


def _create_user_pool(idp, ctx, **kwargs):
    """CreateUserPool + register DeleteUserPool cleanup; returns the UserPool dict."""
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )["UserPool"]
    ctx.on_cleanup(lambda _id=pool["Id"]: idp.delete_user_pool(UserPoolId=_id))
    return pool


def _admin_create_confirmed_user(idp, ctx, pool_id, password=DEFAULT_PASSWORD):
    """Create a user and immediately set a permanent password so the user lands in
    CONFIRMED status, ready to authenticate. Returns the username."""
    username = ctx.unique_name("sim2real-behav-cip-user-")
    idp.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=DEFAULT_PASSWORD,
        MessageAction="SUPPRESS",
    )
    ctx.on_cleanup(
        lambda: idp.admin_delete_user(UserPoolId=pool_id, Username=username)
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    return username


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminListDevices on a pool without DeviceConfiguration is refused with
    InvalidUserPoolConfigurationException and the exact message; after UpdateUserPool enables device
    tracking it returns no devices for a new user."""
    idp = ctx.client("cognito-idp")
    pool = _create_user_pool(idp, ctx)
    username = _admin_create_confirmed_user(idp, ctx, pool["Id"])

    code, message = _error(
        lambda: idp.admin_list_devices(
            UserPoolId=pool["Id"], Username=username, Limit=10
        )
    )
    assert code == "InvalidUserPoolConfigurationException", (
        f"expected InvalidUserPoolConfigurationException without device tracking, got {code}"
    )
    expected_message = "Device tracking not currently enabled for this pool."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    idp.update_user_pool(
        UserPoolId=pool["Id"],
        DeviceConfiguration={
            "ChallengeRequiredOnNewDevice": False,
            "DeviceOnlyRememberedOnUserPrompt": False,
        },
    )

    def list_devices():
        try:
            return idp.admin_list_devices(
                UserPoolId=pool["Id"], Username=username, Limit=10
            ).get("Devices", [])
        except Exception:
            return None

    devices = _poll_until(
        list_devices, lambda d: d is not None, timeout_s=30, interval_s=2
    )
    assert devices == [], (
        f"expected zero tracked devices for a fresh user once tracking is on, got {devices}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
