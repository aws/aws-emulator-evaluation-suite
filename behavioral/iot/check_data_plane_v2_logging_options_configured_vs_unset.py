"""data-plane-v2-logging-options-configured-vs-unset."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-plane-v2-logging-options-configured-vs-unset"
GROUP = "error-semantics"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iot-logging")
def run(ctx) -> None:
    """GetV2LoggingOptions reflects SetV2LoggingOptions (NotConfiguredException before any set), and
    DeleteV2LoggingLevel removes only the target-level override, leaving the account default."""
    iot = ctx.client("iot")

    # an account that never called SetV2LoggingOptions raises NotConfiguredException
    previous = None
    try:
        previous = iot.get_v2_logging_options()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
        assert code == "NotConfiguredException", (
            f"expected NotConfiguredException probing a possibly-unconfigured account, got {code!r}"
        )
        expected_message = "SetV2LoggingOptions was not previously called. No logging options have been set."
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    role_arn = _create_logging_role(ctx)

    def _restore():
        if previous is not None:
            iot.set_v2_logging_options(
                roleArn=previous.get("roleArn", role_arn),
                defaultLogLevel=previous.get("defaultLogLevel", "DISABLED"),
                disableAllLogs=previous.get("disableAllLogs", False),
            )
        else:
            # V2 logging options have no delete operation: the closest state to
            # never-configured is every log disabled.
            iot.set_v2_logging_options(roleArn=role_arn, defaultLogLevel="DISABLED", disableAllLogs=True)

    ctx.on_cleanup(_restore)

    # IoT can reject a just-created role until its trust policy propagates; retry the set only.
    _retry_on_role_propagation(
        lambda: iot.set_v2_logging_options(roleArn=role_arn, defaultLogLevel="WARN", disableAllLogs=False)
    )

    got = _poll_until(
        lambda: iot.get_v2_logging_options(),
        lambda g: g.get("defaultLogLevel") == "WARN",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert got["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {got.get('roleArn')!r}"
    assert got["defaultLogLevel"] == "WARN", f"expected defaultLogLevel WARN, got {got.get('defaultLogLevel')!r}"

    group_name = ctx.unique_name("sim2real-iot-logtarget-")
    iot.create_thing_group(thingGroupName=group_name, tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: iot.delete_thing_group(thingGroupName=group_name))

    iot.set_v2_logging_level(logTarget={"targetType": "THING_GROUP", "targetName": group_name}, logLevel="DEBUG")

    levels = iot.list_v2_logging_levels()["logTargetConfigurations"]
    matching = [lvl for lvl in levels if lvl["logTarget"].get("targetName") == group_name]
    assert len(matching) == 1, f"expected exactly 1 logTargetConfiguration for {group_name!r}, got {len(matching)}"
    assert matching[0]["logLevel"] == "DEBUG", f"expected logLevel DEBUG, got {matching[0]['logLevel']!r}"

    iot.delete_v2_logging_level(targetType="THING_GROUP", targetName=group_name)

    remaining = _poll_until(
        lambda: iot.list_v2_logging_levels()["logTargetConfigurations"],
        lambda ls: not any(lvl["logTarget"].get("targetName") == group_name for lvl in ls),
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not any(lvl["logTarget"].get("targetName") == group_name for lvl in remaining), (
        f"expected {group_name!r} absent from ListV2LoggingLevels after DeleteV2LoggingLevel, still present"
    )

    still_default = iot.get_v2_logging_options()
    assert still_default["defaultLogLevel"] == "WARN", (
        f"expected account-wide defaultLogLevel to remain WARN after deleting the target override, "
        f"got {still_default.get('defaultLogLevel')!r}"
    )
    assert still_default["roleArn"] == role_arn, (
        f"expected account-wide roleArn to remain {role_arn!r} after deleting the target override, "
        f"got {still_default.get('roleArn')!r}"
    )


def _create_logging_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-logrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTLogging"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_on_role_propagation(fn, *, attempts=6, interval_s=3.0):
    """Retry fn() while IoT rejects a just-created role until IAM propagation completes."""
    last_exc = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
