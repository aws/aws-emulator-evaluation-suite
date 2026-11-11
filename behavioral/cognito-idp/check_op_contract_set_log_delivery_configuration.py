"""op-contract-set-log-delivery-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-set-log-delivery-configuration"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetLogDeliveryConfiguration persists the CloudWatch Logs export config; bogus pool id is rejected."""
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")
    sts = ctx.client("sts")

    pool_id = _create_user_pool(ctx)

    log_group_name = ctx.unique_name("/sim2real/cognito-behav-")
    logs.create_log_group(
        logGroupName=log_group_name,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    account_id = sts.get_caller_identity()["Account"]
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group_name}"

    log_configs = [
        {
            "LogLevel": "ERROR",
            "EventSource": "userNotification",
            "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
        }
    ]
    resp = idp.set_log_delivery_configuration(UserPoolId=pool_id, LogConfigurations=log_configs)
    applied = resp["LogDeliveryConfiguration"]["LogConfigurations"]
    assert len(applied) == 1, applied
    assert applied[0]["EventSource"] == "userNotification", applied[0]
    assert applied[0]["LogLevel"] == "ERROR", applied[0]
    assert applied[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn, applied[0]

    fetched = idp.get_log_delivery_configuration(UserPoolId=pool_id)
    fetched_configs = fetched["LogDeliveryConfiguration"]["LogConfigurations"]
    assert fetched_configs == applied, fetched_configs

    bogus_pool_id = "us-east-1_nonexistent"
    code, message = _error(
        lambda: idp.set_log_delivery_configuration(
            UserPoolId=bogus_pool_id, LogConfigurations=log_configs
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = f"UserPool with ID: {bogus_pool_id}does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, **overrides):
    idp = ctx.client("cognito-idp")
    params = {
        "PoolName": ctx.unique_name("sim2real-behav-pool-"),
        "UserPoolTags": {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        "DeletionProtection": "INACTIVE",
    }
    params.update(overrides)
    resp = idp.create_user_pool(**params)
    pool_id = resp["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
