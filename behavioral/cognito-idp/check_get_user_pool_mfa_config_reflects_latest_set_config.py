"""get-user-pool-mfa-config-reflects-latest-set-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-pool-mfa-config-reflects-latest-set-config"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserPoolMfaConfig always reflects the most recently applied SetUserPoolMfaConfig
    settings -- including per-method configuration -- never a stale, previously-set value."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_pool(ctx)

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": True},
        MfaConfiguration="OPTIONAL",
    )
    first = cognito.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert first["MfaConfiguration"] == "OPTIONAL", (
        f"expected MfaConfiguration OPTIONAL after first SetUserPoolMfaConfig, got {first.get('MfaConfiguration')}"
    )
    assert first["SoftwareTokenMfaConfiguration"]["Enabled"] is True, (
        f"expected SoftwareTokenMfaConfiguration.Enabled True after first set, "
        f"got {first.get('SoftwareTokenMfaConfiguration')}"
    )

    cognito.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        SoftwareTokenMfaConfiguration={"Enabled": False},
        MfaConfiguration="OPTIONAL",
    )
    second = cognito.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert second["MfaConfiguration"] == "OPTIONAL", (
        f"expected MfaConfiguration OPTIONAL after second SetUserPoolMfaConfig, got {second.get('MfaConfiguration')}"
    )
    assert second["SoftwareTokenMfaConfiguration"]["Enabled"] is False, (
        f"expected SoftwareTokenMfaConfiguration.Enabled False reflecting the second (latest) set, "
        f"not the stale True from the first set -- got {second.get('SoftwareTokenMfaConfiguration')}"
    )


def _create_pool(ctx):
    cognito = ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
