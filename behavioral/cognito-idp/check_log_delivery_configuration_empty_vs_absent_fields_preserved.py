"""log-delivery-configuration-empty-vs-absent-fields-preserved."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "log-delivery-configuration-empty-vs-absent-fields-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogDeliveryConfiguration returns LogConfigurations as an empty list both before any Set and
    after a Set to zero destinations, identically; a Set with a ":*" LogGroupArn fails with
    InvalidParameterException and its exact message and leaves the configuration unchanged."""
    cognito = ctx.client("cognito-idp")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-logcfg-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    unconfigured = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert "LogConfigurations" in unconfigured
    assert unconfigured["LogConfigurations"] == []
    assert unconfigured["UserPoolId"] == pool_id

    set_result = cognito.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[]
    )["LogDeliveryConfiguration"]
    assert "LogConfigurations" in set_result
    assert set_result["LogConfigurations"] == []

    reread = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert "LogConfigurations" in reread
    assert reread["LogConfigurations"] == []
    assert reread == unconfigured

    bogus_arn = (
        f"arn:aws:logs:{ctx.region}:{account_id}:log-group:"
        f"{ctx.unique_name('/sim2real/behav/cognito-logcfg-bogus-')}:*"
    )
    error = _client_error(
        lambda: cognito.set_log_delivery_configuration(
            UserPoolId=pool_id,
            LogConfigurations=[
                {
                    "LogLevel": "ERROR",
                    "EventSource": "userNotification",
                    "CloudWatchLogsConfiguration": {"LogGroupArn": bogus_arn},
                }
            ],
        )
    )
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException for a wildcard-suffixed LogGroupArn, got {error!r}"
    )
    message = error.get("Message", "")
    expected = (
        f"1 validation error detected: Value '{bogus_arn}' at"
        " 'logConfigurations.1.member.cloudWatchLogsConfiguration.logGroupArn' failed to satisfy"
        " constraint: Member must satisfy regular expression pattern:"
        r" arn:[\w+=/,.@-]+:[\w+=/,.@-]+:([\w+=/,.@-]*)?:[0-9]+:[\w+=/,.@-]+(:[\w+=/,.@-]+)?(:[\w+=/,.@-]+)?"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after_rejection = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_rejection == unconfigured, (
        f"a rejected SetLogDeliveryConfiguration must not change the stored representation, "
        f"got {after_rejection!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected SetLogDeliveryConfiguration to reject a wildcard-suffixed LogGroupArn, "
        f"but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
