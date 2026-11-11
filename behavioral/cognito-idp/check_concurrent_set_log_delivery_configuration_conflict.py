"""concurrent-set-log-delivery-configuration-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-set-log-delivery-configuration-conflict"
GROUP = "concurrency"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent SetLogDeliveryConfiguration writes to different log groups leave exactly one
    complete LogConfigurations entry from one writer, never a merge of both."""
    cognito = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-logpool-"),
        UserPoolTags=_TAGS,
        DeletionProtection="INACTIVE",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    group_a = ctx.unique_name("/sim2real-behav/cognito-log-a-")
    group_b = ctx.unique_name("/sim2real-behav/cognito-log-b-")
    arn_a = _create_log_group(ctx, logs, group_a)
    arn_b = _create_log_group(ctx, logs, group_b)

    def _config_for(arn: str) -> dict:
        return {
            "LogConfigurations": [
                {
                    "LogLevel": "ERROR",
                    "EventSource": "userNotification",
                    "CloudWatchLogsConfiguration": {"LogGroupArn": arn},
                }
            ]
        }

    def _set(arn: str):
        return cognito.set_log_delivery_configuration(UserPoolId=pool_id, **_config_for(arn))

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_set, arn_a)
        fut_b = pool.submit(_set, arn_b)
        fut_a.result()
        fut_b.result()

    final = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    log_configs = final["LogConfigurations"]

    assert len(log_configs) == 1, (
        f"expected exactly one LogConfigurations entry (a full-replacement write), got {log_configs}"
    )
    winner = log_configs[0]
    final_arn = winner["CloudWatchLogsConfiguration"]["LogGroupArn"]
    assert final_arn in (arn_a, arn_b), (
        f"final LogGroupArn {final_arn} is neither racing target {arn_a} nor {arn_b} -- corrupted"
    )
    expected = _config_for(final_arn)["LogConfigurations"][0]
    assert winner == expected, (
        f"final entry {winner} is not an untorn copy of the winning write {expected} "
        "-- a field-level merge/torn-write corrupted the losing writer's fields into the winner"
    )


def _create_log_group(ctx, logs, name: str) -> str:
    logs.create_log_group(logGroupName=name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    arn = next(g["arn"] for g in groups if g["logGroupName"] == name)
    # Cognito's LogGroupArn pattern rejects the trailing ":*" that CloudWatch
    # Logs' own describe_log_groups ARNs include.
    return arn[:-2] if arn.endswith(":*") else arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
