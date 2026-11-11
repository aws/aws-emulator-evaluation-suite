"""get-log-delivery-configuration-returns-empty-before-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-log-delivery-configuration-returns-empty-before-set"
GROUP = "data-plane"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogDeliveryConfiguration on a pool that never had SetLogDeliveryConfiguration
    called returns a LogDeliveryConfiguration with an empty LogConfigurations list --
    it does not raise ResourceNotFoundException just because nothing was configured."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    response = cognito.get_log_delivery_configuration(UserPoolId=pool_id)

    config = response["LogDeliveryConfiguration"]
    assert config["UserPoolId"] == pool_id, f"expected {pool_id}, got {config['UserPoolId']!r}"
    assert config["LogConfigurations"] == [], (
        f"expected no log configurations on a freshly created pool, got {config['LogConfigurations']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
