"""mfa-on-without-method-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mfa-on-without-method-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


def _delete_pool(idp, pool_id: str) -> None:
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a target
    that accepts input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetUserPoolMfaConfig with MfaConfiguration ON and no method fails with InvalidParameterException
    and its exact message and leaves MFA OFF, while OPTIONAL and ON with software tokens take effect."""
    c = ctx.client("cognito-idp")

    # Positive control, on its own pool: a valid SetUserPoolMfaConfig call succeeds and is
    # readable back through an independent GetUserPoolMfaConfig call.
    control_pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-ctrl-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=control_pool_id: _delete_pool(c, _id))

    c.set_user_pool_mfa_config(
        UserPoolId=control_pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    control_read = c.get_user_pool_mfa_config(UserPoolId=control_pool_id)
    assert control_read.get("MfaConfiguration") == "OPTIONAL", (
        "positive control: expected OPTIONAL after a valid SetUserPoolMfaConfig, got "
        f"{control_read.get('MfaConfiguration')}"
    )
    assert control_read.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
        "positive control: expected software-token MFA enabled, got "
        f"{control_read.get('SoftwareTokenMfaConfiguration')}"
    )

    # Break exactly one thing: a fresh pool with no MFA method, told to turn MFA fully ON.
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool(c, _id))

    error = _client_error(
        lambda: c.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="ON")
    )
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException when enabling MFA with no method, got {error.get('Code')}"
    )
    assert error.get("Message") == "Invalid MFA Configuration given. SMS MFA, Email MFA, or Software Token MFA must be enabled.", error.get("Message")

    # Effect absent: the independent read shows the rejected call never moved state off OFF.
    after_reject = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert after_reject.get("MfaConfiguration", "OFF") == "OFF", (
        "a rejected SetUserPoolMfaConfig must not move state off OFF, got "
        f"{after_reject.get('MfaConfiguration')}"
    )

    # Restore: the identical call, now carrying a method, must succeed.
    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="ON",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    after_restore = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert after_restore.get("MfaConfiguration") == "ON", (
        f"expected ON to succeed once a method is attached, got {after_restore.get('MfaConfiguration')}"
    )
    assert after_restore.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
        "expected software-token MFA enabled after restore, got "
        f"{after_restore.get('SoftwareTokenMfaConfiguration')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
