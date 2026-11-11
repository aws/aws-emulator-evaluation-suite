"""op-admin-get-device-nonexistent-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-admin-get-device-nonexistent-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

# A password that satisfies the default Cognito password policy
# (min length 8, upper, lower, number, symbol).
DEFAULT_PASSWORD = "TempPassw0rd!23"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool(idp, ctx, **kwargs):
    """CreateUserPool + register DeleteUserPool cleanup; returns the UserPool dict.

    Real AWS now defaults a freshly created pool to DeletionProtection=ACTIVE, which makes
    DeleteUserPool fail (and this check's cleanup silently leak the pool) unless it is pinned
    to INACTIVE explicitly here.
    """
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
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
    """On a pool without device tracking, AdminGetDevice fails with InvalidParameterException for a
    malformed DeviceKey and with InvalidUserPoolConfigurationException for a well-formed unregistered
    one, each with its exact message, so the two failures stay distinct."""
    idp = ctx.client("cognito-idp")
    pool = _create_user_pool(idp, ctx)
    username = _admin_create_confirmed_user(idp, ctx, pool["Id"])

    malformed_key = "us-west-2_ghost-device-key"
    malformed_code = _client_error(
        lambda: idp.admin_get_device(
            UserPoolId=pool["Id"], Username=username, DeviceKey=malformed_key
        )
    )
    assert malformed_code.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException for a malformed device key, got {malformed_code}"
    )
    assert malformed_code.get("Message") == (
        f"1 validation error detected: Value '{malformed_key}' at 'deviceKey' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-f-]+"
    ), malformed_code.get("Message")

    well_formed_key = f"{ctx.region}_{uuid.uuid4()}"
    well_formed_code = _client_error(
        lambda: idp.admin_get_device(
            UserPoolId=pool["Id"], Username=username, DeviceKey=well_formed_key
        )
    )
    assert well_formed_code.get("Code") == "InvalidUserPoolConfigurationException", (
        "expected InvalidUserPoolConfigurationException for a well-formed but "
        f"unregistered device key on a pool with no device tracking, got {well_formed_code}"
    )
    assert well_formed_code.get("Message") == "Device tracking not currently enabled for this pool.", well_formed_code.get("Message")
    assert well_formed_code.get("Code") != malformed_code.get("Code"), (
        "malformed and well-formed-but-unregistered device keys must fail differently, "
        f"got the same code {malformed_code!r} for both"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
