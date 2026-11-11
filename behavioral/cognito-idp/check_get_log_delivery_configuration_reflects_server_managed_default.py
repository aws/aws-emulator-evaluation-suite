"""get-log-delivery-configuration-reflects-server-managed-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-log-delivery-configuration-reflects-server-managed-default"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogDeliveryConfiguration on a pool never configured returns that pool's id with an empty
    LogConfigurations list, not an error."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)

    resp = cognito.get_log_delivery_configuration(UserPoolId=pool_id)
    config = resp["LogDeliveryConfiguration"]

    assert config["UserPoolId"] == pool_id, f"expected UserPoolId {pool_id!r}, got {config.get('UserPoolId')!r}"
    assert "LogConfigurations" in config, (
        f"LogDeliveryConfiguration is missing the LogConfigurations key entirely, got {config!r}"
    )
    assert config["LogConfigurations"] == [], (
        f"expected an empty default log configuration list, got {config['LogConfigurations']!r}"
    )


def _create_user_pool(ctx, cognito, **overrides):
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    }
    params.update(overrides)
    pool_id = cognito.create_user_pool(**params)["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
