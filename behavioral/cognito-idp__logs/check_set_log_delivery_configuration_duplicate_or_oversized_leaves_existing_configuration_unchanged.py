"""set-log-delivery-configuration-duplicate-or-oversized-leaves-existing-configuration-unchanged."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-log-delivery-configuration-duplicate-or-oversized-leaves-existing-configuration-unchanged"
GROUP = "error-semantics"
SERVICES = ["cognito-idp", "logs"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); raise if it succeeds instead."""
    try:
        result = fn()
    except ClientError as exc:
        actual_code = exc.response["Error"]["Code"]
        actual_message = exc.response["Error"].get("Message", "")
        assert (actual_code, actual_message) == (code, message), (
            f"expected ({code!r}, {message!r}), got ({actual_code!r}, {actual_message!r})"
        )
        return
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetLogDeliveryConfiguration rejects a list repeating one event source and a list over 2
    entries, leaving an already non-empty configuration exactly as it was; a 2-entry list naming
    each of the two distinct event sources once is accepted and read back exactly.
    """
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-logdup-pool-"),
        UserPoolTags=_TAGS,
        UserPoolTier="PLUS",
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    log_group_name = ctx.unique_name("/sim2real/behav/cognito-logdup-")
    logs.create_log_group(logGroupName=log_group_name, tags=_TAGS)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[: -len(":*")]

    notification_entry = {
        "LogLevel": "ERROR",
        "EventSource": "userNotification",
        "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
    }
    auth_events_entry = {
        "LogLevel": "INFO",
        "EventSource": "userAuthEvents",
        "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
    }

    # Establish a non-empty baseline before either refused Set is attempted.
    baseline = idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[notification_entry]
    )["LogDeliveryConfiguration"]
    assert baseline["LogConfigurations"] == [notification_entry], (
        f"expected the baseline Set to persist exactly, got {baseline['LogConfigurations']!r}"
    )
    confirmed_baseline = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert confirmed_baseline["LogConfigurations"] == [notification_entry], (
        f"expected GetLogDeliveryConfiguration to reflect the baseline, got "
        f"{confirmed_baseline['LogConfigurations']!r}"
    )

    repeated_entry_repr = (
        f"LogConfigurationType(logLevel=ERROR, eventSource=userNotification, "
        f"cloudWatchLogsConfiguration=CloudWatchLogsConfigurationType(logGroupArn={log_group_arn}), "
        f"s3Configuration=null, firehoseConfiguration=null)"
    )
    _DUPLICATE_EVENT_SOURCE = (
        "InvalidParameterException",
        "Request validation Failed. Following event sources appear more then once in a request: "
        "[userNotification].",
    )
    _expect_error(
        lambda: idp.set_log_delivery_configuration(
            UserPoolId=pool_id,
            LogConfigurations=[notification_entry, notification_entry],
        ),
        *_DUPLICATE_EVENT_SOURCE,
    )
    after_duplicate = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_duplicate["LogConfigurations"] == [notification_entry], (
        "a rejected duplicate-event-source Set must leave the existing configuration unchanged, got "
        f"{after_duplicate['LogConfigurations']!r}"
    )

    _OVERSIZED_LIST = (
        "InvalidParameterException",
        f"1 validation error detected: Value '[{', '.join([repeated_entry_repr] * 3)}]' at "
        f"'logConfigurations' failed to satisfy constraint: Member must have length less than or "
        f"equal to 2",
    )
    _expect_error(
        lambda: idp.set_log_delivery_configuration(
            UserPoolId=pool_id,
            LogConfigurations=[notification_entry, notification_entry, notification_entry],
        ),
        *_OVERSIZED_LIST,
    )
    after_oversized = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_oversized["LogConfigurations"] == [notification_entry], (
        "a rejected oversized Set must leave the existing configuration unchanged, got "
        f"{after_oversized['LogConfigurations']!r}"
    )

    # Positive control: a 2-entry list naming each of the two distinct event sources once is
    # accepted and replaces the baseline exactly -- compared as a set of full canonicalized
    # entries, not keyed by EventSource, so a duplicated or extra entry would be caught.
    expected_pair = {
        json.dumps(notification_entry, sort_keys=True),
        json.dumps(auth_events_entry, sort_keys=True),
    }
    applied = idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[notification_entry, auth_events_entry]
    )["LogDeliveryConfiguration"]
    applied_cfgs = applied["LogConfigurations"]
    assert len(applied_cfgs) == 2, f"expected exactly 2 log configurations, got {applied_cfgs!r}"
    applied_pair = {json.dumps(cfg, sort_keys=True) for cfg in applied_cfgs}
    assert applied_pair == expected_pair, (
        f"expected the set-response entries to be exactly {expected_pair!r}, got {applied_pair!r}"
    )

    confirmed = idp.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    confirmed_cfgs = confirmed["LogConfigurations"]
    assert len(confirmed_cfgs) == 2, f"expected exactly 2 log configurations, got {confirmed_cfgs!r}"
    confirmed_pair = {json.dumps(cfg, sort_keys=True) for cfg in confirmed_cfgs}
    assert confirmed_pair == expected_pair, (
        f"expected GetLogDeliveryConfiguration to read back exactly {expected_pair!r}, got "
        f"{confirmed_pair!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
