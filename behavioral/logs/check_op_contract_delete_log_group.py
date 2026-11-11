"""op-contract-delete-log-group."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-log-group"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteLogGroup: success path removes the group (and its streams) so it no longer
    appears in DescribeLogGroups; error boundaries are ResourceNotFoundException for a
    missing group and InvalidParameterException when deletion protection is enabled."""
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    logs.create_log_stream(logGroupName=group_name, logStreamName="s1")

    logs.delete_log_group(logGroupName=group_name)

    def _gone() -> bool:
        resp = logs.describe_log_groups(logGroupNamePrefix=group_name)
        return not any(g["logGroupName"] == group_name for g in resp.get("logGroups", []))

    assert _poll_until(_gone, timeout_s=30, interval_s=1.0), "log group still visible after delete"

    # error boundary 1: not found
    error = _expect_error(lambda: logs.delete_log_group(logGroupName=group_name))
    assert error.get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    expected_message = "The specified log group does not exist."
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # error boundary 2: deletion protection blocks delete
    protected_name = ctx.unique_name("sim2real-behav-lg-protected-")
    logs.create_log_group(logGroupName=protected_name, tags={"Sim2RealOwner": "behavioral-suite"})
    logs.put_log_group_deletion_protection(
        logGroupIdentifier=protected_name, deletionProtectionEnabled=True
    )

    def _cleanup_protected():
        _ignore_not_found(
            lambda: logs.put_log_group_deletion_protection(
                logGroupIdentifier=protected_name, deletionProtectionEnabled=False
            )
        )
        _ignore_not_found(lambda: logs.delete_log_group(logGroupName=protected_name))

    ctx.on_cleanup(_cleanup_protected)

    error = _expect_error(lambda: logs.delete_log_group(logGroupName=protected_name))
    assert error.get("Code") == "InvalidParameterException", (
        f"expected InvalidParameterException, got {error!r}"
    )
    expected_message = (
        "LogGroup has delete protection enabled. "
        "Disable delete protection before attempting to delete the resource."
    )
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # the rejected delete must not have partially applied: the group is still there.
    still_there = logs.describe_log_groups(logGroupNamePrefix=protected_name)
    assert any(g["logGroupName"] == protected_name for g in still_there.get("logGroups", [])), (
        f"{protected_name} disappeared despite the delete being rejected"
    )

    # restore: disabling protection makes the identical delete succeed.
    logs.put_log_group_deletion_protection(
        logGroupIdentifier=protected_name, deletionProtectionEnabled=False
    )
    logs.delete_log_group(logGroupName=protected_name)
    assert _poll_until(
        lambda: not any(
            g["logGroupName"] == protected_name
            for g in logs.describe_log_groups(logGroupNamePrefix=protected_name).get("logGroups", [])
        ),
        timeout_s=30,
        interval_s=1.0,
    ), f"{protected_name} still visible after protection was disabled and delete retried"


def _expect_error(fn):
    """Call fn(); return the botocore Error dict. Raises if fn() unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _ignore_not_found(fn):
    """Teardown helper: a resource the check already deleted is not a teardown failure."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _poll_until(probe, *, timeout_s=30.0, interval_s=1.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if probe():
            return True
        time.sleep(interval_s)
    return probe()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
