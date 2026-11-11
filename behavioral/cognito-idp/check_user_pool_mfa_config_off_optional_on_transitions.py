"""user-pool-mfa-config-off-optional-on-transitions."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "user-pool-mfa-config-off-optional-on-transitions"
GROUP = 'mfa-configuration'
SERVICES = ['cognito-idp']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetUserPoolMfaConfig walks a pool OFF -> OPTIONAL -> ON -> OFF, and GetUserPoolMfaConfig
    reflects each state plus the software-token sub-configuration (absent again once OFF)."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))

    initial = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert initial["MfaConfiguration"] == "OFF", initial

    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    optional_cfg = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert optional_cfg["MfaConfiguration"] == "OPTIONAL", optional_cfg["MfaConfiguration"]
    assert optional_cfg.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
        optional_cfg.get("SoftwareTokenMfaConfiguration")
    )

    c.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="ON",
    )
    on_cfg = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert on_cfg["MfaConfiguration"] == "ON", on_cfg["MfaConfiguration"]
    assert on_cfg.get("SoftwareTokenMfaConfiguration", {}).get("Enabled") is True, (
        on_cfg.get("SoftwareTokenMfaConfiguration")
    )

    c.set_user_pool_mfa_config(UserPoolId=pool_id, MfaConfiguration="OFF")
    off_cfg = c.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert off_cfg["MfaConfiguration"] == "OFF", off_cfg["MfaConfiguration"]
    assert "SoftwareTokenMfaConfiguration" not in off_cfg, (
        "MFA is OFF with no SoftwareTokenMfaConfiguration in the request, but "
        f"GetUserPoolMfaConfig still carries one: {off_cfg.get('SoftwareTokenMfaConfiguration')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
