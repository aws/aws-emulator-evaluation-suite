"""log-delivery-configuration-roundtrip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-delivery-configuration-roundtrip"
GROUP = "server-side"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetLogDeliveryConfiguration is durably stored and returned by GetLogDeliveryConfiguration."""

    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_name = ctx.unique_name("sim2real-behav-logcfg-")
    pool_id = idp.create_user_pool(
        PoolName=pool_name, DeletionProtection="INACTIVE", UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_pool_if_present(idp, pool_id))

    log_group_name = ctx.unique_name("/sim2real/behav-cognito-")
    logs.create_log_group(logGroupName=log_group_name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    described = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert len(described) == 1
    log_group_arn = described[0]["arn"]
    # CloudWatch Logs returns the ARN with a trailing ":*" wildcard suffix, but Cognito's
    # LogGroupArn field is validated against a pattern that rejects that suffix.
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    log_configs = [
        {
            "LogLevel": "ERROR",
            "EventSource": "userNotification",
            "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
        }
    ]
    try:
        set_resp = idp.set_log_delivery_configuration(
            UserPoolId=pool_id, LogConfigurations=log_configs
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "FeatureUnavailableInTierException":
            raise AssertionError("unreachable: log export unavailable for this pool's feature tier")
        raise

    set_out = set_resp["LogDeliveryConfiguration"]["LogConfigurations"]
    assert len(set_out) == 1
    assert set_out[0]["LogLevel"] == "ERROR"
    assert set_out[0]["EventSource"] == "userNotification"
    assert set_out[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn

    got = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    got_configs = got["LogConfigurations"]
    assert got["UserPoolId"] == pool_id
    assert len(got_configs) == 1
    assert got_configs[0]["LogLevel"] == "ERROR"
    assert got_configs[0]["EventSource"] == "userNotification"
    assert got_configs[0]["CloudWatchLogsConfiguration"]["LogGroupArn"] == log_group_arn

    idp.delete_user_pool(UserPoolId=pool_id)
    try:
        idp.describe_user_pool(UserPoolId=pool_id)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", e.response["Error"]
        message = e.response["Error"].get("Message", "")
    else:
        raise AssertionError(f"user pool {pool_id} still describable after DeleteUserPool")
    expected = f"User pool {pool_id} does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _delete_pool_if_present(idp, pool_id):
    """Teardown for the pool: the check deletes it itself, so only a leftover is removed."""
    try:
        idp.delete_user_pool(UserPoolId=pool_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
