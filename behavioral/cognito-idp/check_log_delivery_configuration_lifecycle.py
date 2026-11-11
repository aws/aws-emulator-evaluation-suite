"""log-delivery-configuration-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "log-delivery-configuration-lifecycle"
GROUP = 'state-machine'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogDeliveryConfiguration reads back a userNotification ERROR configuration to log group A,
    its full replacement by INFO to log group B, and an empty list after removal."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))

    logs = ctx.client("logs")
    arn_a = _new_log_group(ctx, logs, "sim2real-behav-cip-loggroup-a-")
    arn_b = _new_log_group(ctx, logs, "sim2real-behav-cip-loggroup-b-")

    # 1. configure
    c.set_log_delivery_configuration(
        UserPoolId=pool_id,
        LogConfigurations=[
            {
                "LogLevel": "ERROR",
                "EventSource": "userNotification",
                "CloudWatchLogsConfiguration": {"LogGroupArn": arn_a},
            }
        ],
    )
    configured = c.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    configs = configured["LogConfigurations"]
    assert len(configs) == 1, configs
    assert configs[0]["EventSource"] == "userNotification", configs[0]
    assert configs[0]["LogLevel"] == "ERROR", configs[0]
    assert configs[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == arn_a, configs[0]

    # 2. update in place: a different level and destination must fully replace the
    # first entry, not merge alongside it.
    c.set_log_delivery_configuration(
        UserPoolId=pool_id,
        LogConfigurations=[
            {
                "LogLevel": "INFO",
                "EventSource": "userNotification",
                "CloudWatchLogsConfiguration": {"LogGroupArn": arn_b},
            }
        ],
    )
    updated = c.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    updated_configs = updated["LogConfigurations"]
    assert len(updated_configs) == 1, updated_configs
    assert updated_configs[0]["LogLevel"] == "INFO", updated_configs[0]
    assert updated_configs[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == arn_b, updated_configs[0]

    # 3. remove: an explicit empty list clears delivery entirely.
    c.set_log_delivery_configuration(UserPoolId=pool_id, LogConfigurations=[])
    removed = c.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert removed["LogConfigurations"] == [], removed


def _new_log_group(ctx, logs, prefix: str) -> str:
    log_group_name = f"/{ctx.unique_name(prefix)}"
    logs.create_log_group(logGroupName=log_group_name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name).get("logGroups", [])
    assert groups, f"log group {log_group_name} not found immediately after creation"
    arn = groups[0]["arn"]
    # CloudWatch Logs appends a ":*" wildcard suffix Cognito's ARN validation rejects.
    return arn[: -len(":*")] if arn.endswith(":*") else arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
