"""delete-syslog-configuration-active-listener-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-syslog-configuration-active-listener-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSyslogConfiguration on a log group with no syslog configuration raises InvalidParameterException
    with its exact message, the group remains, and still no syslog configuration exists.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))

    # DeleteSyslogConfiguration's logGroupIdentifier field validates as an ARN
    # (the plain log group name fails input validation with
    # InvalidParameterException before the "does a config exist" business
    # logic ever runs), so we must pass the group's ARN -- with the
    # `describe_log_groups`-supplied trailing ":*" wildcard suffix stripped,
    # since that suffix isn't valid in this identifier field either -- to
    # actually reach the not-found boundary this check targets.
    group_arn = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"][0]["arn"]
    if group_arn.endswith(":*"):
        group_arn = group_arn[: -len(":*")]

    # Precondition: no syslog configuration exists for this log group yet --
    # this is the exact condition the rejection below is supposed to detect.
    baseline = logs.list_syslog_configurations(logGroupIdentifier=group_arn)["syslogConfigurations"]
    assert baseline == [], f"expected no syslog configuration to pre-exist, got {baseline}"

    # On real AWS, DeleteSyslogConfiguration for a log group with no syslog
    # configuration is refused with InvalidParameterException (not
    # ResourceNotFoundException), and the refusal names the absent
    # vpcEndpointId rather than a missing configuration.
    error = _expect_error(lambda: logs.delete_syslog_configuration(logGroupIdentifier=group_arn))
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException deleting a non-existent syslog configuration, "
        f"got {error!r}"
    )
    expected_message = "vpcEndpointId is required"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # The rejected delete must have had no effect: an independent read (a
    # different operation than the one that was rejected) shows the log
    # group is untouched and still has zero syslog configurations.
    surviving = logs.describe_log_groups(logGroupNamePrefix=group)["logGroups"]
    assert any(g["logGroupName"] == group for g in surviving), (
        f"expected log group {group} to survive the rejected delete, got {surviving}"
    )
    after = logs.list_syslog_configurations(logGroupIdentifier=group_arn)["syslogConfigurations"]
    assert after == [], f"expected still no syslog configuration after the rejected delete, got {after}"


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
