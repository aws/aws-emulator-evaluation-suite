"""log-delivery-configuration-empty-array-vs-absent-preserved."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "log-delivery-configuration-empty-array-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-empty LogConfigurations list set via SetLogDeliveryConfiguration is read back verbatim, and an
    explicit empty list set afterwards is preserved as an explicit `[]` on read-back — not merged back with the
    prior non-empty entry and not reverted to whatever the pre-configuration baseline shape was."""
    cognito = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    pool_id = cognito.create_user_pool(PoolName=ctx.unique_name("sim2real-logdeliv-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    baseline = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    # AWS's real baseline shape is an explicit empty list (not an absent key) — record it as the ground truth,
    # rather than assuming a specific representation up front.
    assert baseline.get("LogConfigurations", []) == [], (
        f"expected no log configurations before any Set call, got {baseline!r}"
    )

    log_group_name = ctx.unique_name("/sim2real/behav/cognito-logdeliv-")
    logs.create_log_group(logGroupName=log_group_name)
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn[:-2]

    nonempty_cfg = [{
        "EventSource": "userNotification",
        "LogLevel": "ERROR",
        "CloudWatchLogsConfiguration": {"LogGroupArn": log_group_arn},
    }]
    set_nonempty = _set_log_delivery_with_retry(ctx, cognito, pool_id, nonempty_cfg)
    assert set_nonempty["LogConfigurations"] == nonempty_cfg, (
        "SetLogDeliveryConfiguration did not echo the non-empty config back exactly"
    )

    after_nonempty = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert after_nonempty["LogConfigurations"] == nonempty_cfg, (
        f"GetLogDeliveryConfiguration did not preserve the non-empty config, got {after_nonempty!r}"
    )

    # Now explicitly clear it back to an empty list.
    set_resp = cognito.set_log_delivery_configuration(UserPoolId=pool_id, LogConfigurations=[])
    assert set_resp["LogDeliveryConfiguration"]["LogConfigurations"] == [], (
        "SetLogDeliveryConfiguration([]) response should echo an explicit empty list"
    )

    after = cognito.get_log_delivery_configuration(UserPoolId=pool_id)["LogDeliveryConfiguration"]
    assert "LogConfigurations" in after, "LogConfigurations key vanished after being explicitly set to []"
    assert after["LogConfigurations"] == [], (
        f"expected an explicit empty list after SetLogDeliveryConfiguration([]), "
        f"got {after['LogConfigurations']!r} (prior non-empty config leaked through?)"
    )
    assert after["UserPoolId"] == pool_id, (
        f"expected GetLogDeliveryConfiguration to echo UserPoolId {pool_id!r}, got {after.get('UserPoolId')!r}"
    )


def _set_log_delivery_with_retry(ctx, cognito, pool_id: str, configs, timeout_s: float = 60.0):
    """The CloudWatch log group ARN can take a moment to be resolvable by Cognito right after creation."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.set_log_delivery_configuration(
                UserPoolId=pool_id, LogConfigurations=configs
            )["LogDeliveryConfiguration"]
        except cognito.exceptions.InvalidParameterException as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"SetLogDeliveryConfiguration never succeeded within {timeout_s}s: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
