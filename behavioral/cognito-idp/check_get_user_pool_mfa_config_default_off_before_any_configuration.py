"""get-user-pool-mfa-config-default-off-before-any-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-user-pool-mfa-config-default-off-before-any-configuration"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetUserPoolMfaConfig on a fresh pool returns MfaConfiguration=OFF, and the same read
    reflects a later SetUserPoolMfaConfig, so OFF is real state, not a constant."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)

    resp = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert resp["MfaConfiguration"] == "OFF", (
        f"expected MfaConfiguration OFF on a fresh pool, got {resp['MfaConfiguration']!r}"
    )

    idp.set_user_pool_mfa_config(
        UserPoolId=pool_id,
        MfaConfiguration="OPTIONAL",
        SoftwareTokenMfaConfiguration={"Enabled": True},
    )
    changed = idp.get_user_pool_mfa_config(UserPoolId=pool_id)
    assert changed["MfaConfiguration"] == "OPTIONAL", (
        f"expected MfaConfiguration OPTIONAL after set_user_pool_mfa_config, got "
        f"{changed['MfaConfiguration']!r}"
    )


def _create_user_pool(ctx, **kwargs):
    idp = ctx.client("cognito-idp")
    name = ctx.unique_name("sim2real-pool-")
    tags_kwargs = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"}
    tags_kwargs.update(kwargs.pop("UserPoolTags", {}))
    resp = idp.create_user_pool(PoolName=name, UserPoolTags=tags_kwargs, **kwargs)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
