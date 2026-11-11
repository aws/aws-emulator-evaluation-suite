"""op-contract-get-log-delivery-configuration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-log-delivery-configuration"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogDeliveryConfiguration round-trips exactly what SetLogDeliveryConfiguration
    wrote (log group ARN, log level, event source), and rejects a nonexistent pool."""
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    log_group_name = ctx.unique_name("/sim2real/behav/cognito-")
    logs.create_log_group(logGroupName=log_group_name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    # CloudWatch Logs returns log-group ARNs with a trailing ":*" wildcard suffix (a
    # CloudWatch Logs convention for the "any log stream" ARN form). Cognito's
    # SetLogDeliveryConfiguration validates LogGroupArn against the plain log-group ARN
    # and rejects the ":*" suffix with InvalidParameterException, so strip it.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    idp.set_log_delivery_configuration(
        UserPoolId=pool_id,
        LogConfigurations=[
            {
                "LogLevel": "ERROR",
                "EventSource": "userNotification",
                "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
            }
        ],
    )

    # success path: the get echoes back exactly what was set
    got = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert got["UserPoolId"] == pool_id, f"expected UserPoolId {pool_id!r}, got {got['UserPoolId']!r}"
    configs = got["LogConfigurations"]
    assert len(configs) == 1, f"expected exactly 1 log configuration, got {len(configs)}"
    assert configs[0]["LogLevel"] == "ERROR", f"expected LogLevel ERROR, got {configs[0]['LogLevel']!r}"
    assert configs[0]["EventSource"] == "userNotification", (
        f"expected EventSource userNotification, got {configs[0]['EventSource']!r}"
    )
    assert configs[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn, (
        f"expected LogGroupArn {log_group_arn!r}, got "
        f"{configs[0]['CloudWatchLogsConfiguration']['LogGroupArn']!r}"
    )

    # distinct error boundary: a nonexistent pool is rejected
    fake_id = f"{ctx.region}_ZZZZZZZZZ"
    code, message = _error(lambda: idp.get_log_delivery_configuration(UserPoolId=fake_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    expected = f"User pool {fake_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
