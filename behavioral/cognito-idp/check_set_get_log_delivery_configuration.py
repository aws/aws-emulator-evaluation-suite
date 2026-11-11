"""set-get-log-delivery-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "set-get-log-delivery-configuration"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetLogDeliveryConfiguration persists log destination configuration returned by GetLogDeliveryConfiguration."""
    cognito = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-logcfg-pool"),
        DeletionProtection="INACTIVE",
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-logcfg"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    log_group_name = ctx.unique_name("/sim2real/cognito-log-delivery")
    logs.create_log_group(
        logGroupName=log_group_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-logcfg"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
        "logGroups"
    ][0]["arn"]
    # CloudWatch Logs returns log group ARNs with a trailing ":*" wildcard suffix,
    # but Cognito's SetLogDeliveryConfiguration validates the ARN strictly and
    # rejects that suffix (InvalidParameterException). Strip it before use.
    log_group_arn_clean = log_group_arn[:-2] if log_group_arn.endswith(":*") else log_group_arn

    log_configurations = [
        {
            "LogLevel": "ERROR",
            "EventSource": "userNotification",
            "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn_clean},
        }
    ]

    set_resp = cognito.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=log_configurations
    )
    set_cfgs = set_resp["LogDeliveryConfiguration"]["LogConfigurations"]
    assert len(set_cfgs) == 1, f"expected 1 log configuration in set response, got {set_cfgs!r}"
    assert set_cfgs[0]["EventSource"] == "userNotification", set_cfgs[0]
    assert set_cfgs[0]["LogLevel"] == "ERROR", set_cfgs[0]
    assert set_cfgs[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn_clean, (
        f"set response echoed {set_cfgs[0]['CloudWatchLogsConfiguration']!r}, "
        f"expected LogGroupArn {log_group_arn_clean!r}"
    )

    get_resp = cognito.get_log_delivery_configuration(UserPoolId=pool_id)
    got_cfgs = get_resp["LogDeliveryConfiguration"]["LogConfigurations"]
    assert len(got_cfgs) == 1, f"expected 1 log configuration, got {got_cfgs!r}"
    got = got_cfgs[0]
    assert got["EventSource"] == "userNotification", got
    assert got["LogLevel"] == "ERROR", got
    assert got["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn_clean, (
        f"expected LogGroupArn {log_group_arn_clean!r}, "
        f"got {got['CloudWatchLogsConfiguration']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
