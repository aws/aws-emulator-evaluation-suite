"""set-log-delivery-configuration-rejected-requests-leave-configuration-unchanged."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-log-delivery-configuration-rejected-requests-leave-configuration-unchanged"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetLogDeliveryConfiguration rejects a no-destination entry and a list over 2 entries, and
    GetLogDeliveryConfiguration stays empty after each, so a rejected Set is never partially applied.
    """
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-logdeliv-pool-"), UserPoolTags=_TAGS
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    baseline = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert baseline["LogConfigurations"] == [], (
        f"expected no log configurations before any Set call, got {baseline['LogConfigurations']!r}"
    )

    no_destination_code, no_destination_message = _error(
        lambda: idp.set_log_delivery_configuration(
            UserPoolId=pool_id,
            LogConfigurations=[{"LogLevel": "ERROR", "EventSource": "userNotification"}],
        )
    )
    no_destination_expected = (
        "Request validation Failed. Following event sources in request have no destination: "
        "[userNotification]."
    )
    assert (no_destination_code, no_destination_message) == (
            "InvalidParameterException", no_destination_expected), (
        f"expected InvalidParameterException {no_destination_expected!r} for a LogConfiguration "
        f"with no destination, got {no_destination_code!r}: {no_destination_message!r}"
    )
    after_no_destination = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_no_destination["LogConfigurations"] == [], (
        f"a rejected no-destination Set must not persist anything, got {after_no_destination['LogConfigurations']!r}"
    )

    # Each entry is valid on its own, so the rejection is about the list length.
    log_group_name = ctx.unique_name("/sim2real/behav/cognito-logdeliv-")
    logs.create_log_group(logGroupName=log_group_name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    valid_entry = {
        "LogLevel": "ERROR",
        "EventSource": "userNotification",
        "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
    }
    oversized_code, oversized_message = _error(
        lambda: idp.set_log_delivery_configuration(
            UserPoolId=pool_id, LogConfigurations=[valid_entry, valid_entry, valid_entry]
        )
    )
    # The service's own length constraint, rendered over its model types for each entry.
    entry_repr = (
        f"LogConfigurationType(logLevel=ERROR, eventSource=userNotification, "
        f"cloudWatchLogsConfiguration=CloudWatchLogsConfigurationType(logGroupArn={log_group_arn}), "
        f"s3Configuration=null, firehoseConfiguration=null)"
    )
    oversized_expected = (
        f"1 validation error detected: Value '[{', '.join([entry_repr] * 3)}]' at "
        f"'logConfigurations' failed to satisfy constraint: Member must have length less than or "
        f"equal to 2"
    )
    assert (oversized_code, oversized_message) == ("InvalidParameterException", oversized_expected), (
        f"expected InvalidParameterException {oversized_expected!r} for a 3-entry "
        f"LogConfigurations list, got {oversized_code!r}: {oversized_message!r}"
    )
    after_oversized = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_oversized["LogConfigurations"] == [], (
        f"a rejected oversized Set must not persist anything, got {after_oversized['LogConfigurations']!r}"
    )

    # Positive control: the same entry alone succeeds and persists.
    applied = idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[valid_entry]
    )["LogDeliveryConfiguration"]
    assert applied["LogConfigurations"] == [valid_entry], (
        f"expected the valid single-entry Set to persist exactly, got {applied['LogConfigurations']!r}"
    )
    confirmed = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert confirmed["LogConfigurations"] == [valid_entry], (
        f"expected GetLogDeliveryConfiguration to reflect the valid Set, got {confirmed['LogConfigurations']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success fails the check."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
