"""obs-cognito-idp-1-log-delivery-config."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "obs-cognito-idp-1-log-delivery-config"
GROUP = "log-delivery"
SERVICES = ["cognito-idp", "logs"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
# SetLogDeliveryConfiguration's refusal of a log-group ARN that does not resolve.
_INVALID_DESTINATION = "Invalid destination in the input."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cognito accepts a userAuthEvents log-group destination only while the group exists, refusing
    a never-created or deleted group's ARN without changing the stored configuration; the config
    moves configured -> cleared -> re-pointed."""
    idp = ctx.client("cognito-idp")
    logs = ctx.client("logs")

    group_a, arn_a = _new_log_group(ctx, logs, "sim2real-xsvc-cip-ldc-a-")

    pool_id = _retry_throttled(lambda: idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-ldc-pool-"),
        UserPoolTier="PLUS",
        UserPoolTags=_TAGS,
    ))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    tier = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("UserPoolTier")
    assert tier == "PLUS", f"pool was created with UserPoolTier={tier!r}, expected 'PLUS'"

    ghost_name = f"/{ctx.unique_name('sim2real-xsvc-cip-ldc-ghost-')}"
    ghost_arn = arn_a.rsplit(":", 1)[0] + ":" + ghost_name
    assert ghost_arn != arn_a and ghost_arn.endswith(ghost_name), f"bad ghost ARN {ghost_arn!r}"
    code, msg = _error(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[_auth_events(ghost_arn)]))
    assert code == "InvalidParameterException", (
        f"a never-created log group as destination: expected InvalidParameterException, "
        f"got {code!r} ({msg!r})")
    assert msg == _INVALID_DESTINATION, (
        f"a never-created log group as destination: expected message {_INVALID_DESTINATION!r}, "
        f"got {msg!r}")
    after_ghost = _configs(idp, pool_id)
    assert after_ghost == [], f"a refused destination must not persist, read back {after_ghost!r}"

    _retry_throttled(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[_auth_events(arn_a)]))
    configured = _configs(idp, pool_id)
    _assert_single_destination(configured, arn_a, "after configuring log group A")

    _retry_throttled(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[]))
    cleared = _configs(idp, pool_id)
    assert cleared == [], f"after LogConfigurations=[] the delivery must be gone, read back {cleared!r}"

    _group_b, arn_b = _new_log_group(ctx, logs, "sim2real-xsvc-cip-ldc-b-")
    assert arn_b != arn_a, f"two log groups minted the same ARN {arn_a!r}"
    _retry_throttled(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[_auth_events(arn_b)]))
    repointed = _configs(idp, pool_id)
    _assert_single_destination(repointed, arn_b, "after re-pointing to log group B")

    # Cognito resolves the destination at set time, so a once-accepted ARN is refused after deletion.
    logs.delete_log_group(logGroupName=group_a)
    gone = [g["logGroupName"] for g in _all_groups(logs, group_a) if g["logGroupName"] == group_a]
    assert gone == [], f"log group {group_a!r} still listed after DeleteLogGroup: {gone!r}"
    code, msg = _error(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[_auth_events(arn_a)]))
    assert code == "InvalidParameterException", (
        f"a deleted log group's ARN as destination: expected InvalidParameterException, "
        f"got {code!r} ({msg!r})")
    assert msg == _INVALID_DESTINATION, (
        f"a deleted log group's ARN as destination: expected message {_INVALID_DESTINATION!r}, "
        f"got {msg!r}")
    after_deleted = _configs(idp, pool_id)
    _assert_single_destination(after_deleted, arn_b, "after the refused re-point to deleted group A")


def _auth_events(arn: str) -> dict:
    return {
        "EventSource": "userAuthEvents",
        "LogLevel": "INFO",
        "CloudWatchLogsConfiguration": {"LogGroupArn": arn},
    }


def _configs(idp, pool_id: str) -> list:
    return idp.get_log_delivery_configuration(UserPoolId=pool_id)[
        "LogDeliveryConfiguration"].get("LogConfigurations", [])


def _assert_single_destination(configs: list, arn: str, when: str) -> None:
    assert len(configs) == 1, f"{when}: expected exactly one log configuration, got {configs!r}"
    cfg = configs[0]
    assert cfg.get("EventSource") == "userAuthEvents", f"{when}: EventSource {cfg!r}"
    assert cfg.get("LogLevel") == "INFO", f"{when}: LogLevel {cfg!r}"
    dest = (cfg.get("CloudWatchLogsConfiguration") or {}).get("LogGroupArn")
    assert dest == arn, f"{when}: destination {dest!r}, expected {arn!r}"
    others = [k for k in ("FirehoseConfiguration", "S3Configuration") if cfg.get(k)]
    assert others == [], f"{when}: unexpected extra destinations {others!r} in {cfg!r}"


def _all_groups(logs, prefix: str) -> list:
    out, kw = [], {"logGroupNamePrefix": prefix}
    while True:
        page = logs.describe_log_groups(**kw)
        out.extend(page.get("logGroups", []))
        if not page.get("nextToken"):
            return out
        kw["nextToken"] = page["nextToken"]


def _new_log_group(ctx, logs, prefix: str) -> tuple[str, str]:
    name = f"/{ctx.unique_name(prefix)}"
    logs.create_log_group(logGroupName=name, tags=_TAGS)
    ctx.on_cleanup(lambda: _delete_log_group_if_present(logs, name))
    match = [g for g in _all_groups(logs, name) if g["logGroupName"] == name]
    assert len(match) == 1, f"log group {name!r} not listed exactly once after create: {match!r}"
    arn = match[0]["arn"]
    # DescribeLogGroups appends ":*" (all streams); Cognito wants the bare log-group ARN.
    return name, arn[: -len(":*")] if arn.endswith(":*") else arn


def _delete_log_group_if_present(logs, name: str) -> None:
    """Teardown: the check itself deletes log group A, so not-found is the expected end state."""
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn(); return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _retry_throttled(fn, *, attempts: int = 8):
    delay = 1.0
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TooManyRequestsException" and i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
