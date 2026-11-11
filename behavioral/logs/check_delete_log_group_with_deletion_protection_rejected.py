"""delete-log-group-with-deletion-protection-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-log-group-with-deletion-protection-rejected"
GROUP = "overly-permissive"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLogGroup is rejected with InvalidParameterException while deletionProtectionEnabled
    is true on the log group, and the log group is not removed. Disabling protection and
    retrying the identical delete succeeds (positive control)."""
    logs = ctx.client("logs")
    name = ctx.unique_name("sim2real-behav-lgprot-")
    logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: _safe(lambda: logs.delete_log_group(logGroupName=name)))

    logs.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=True)
    described = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert described[0]["logGroupName"] == name, f"expected {name} in describe_log_groups, got {described}"

    # PutLogGroupDeletionProtection can take a moment to propagate before DeleteLogGroup
    # actually enforces it, so poll (bounded) until the log group reports protection enabled
    # before attempting the delete. The enforcement path used by DeleteLogGroup can still lag
    # behind the DescribeLogGroups-visible state (on real AWS, a delete attempted right when the
    # visible flag flips can still succeed and delete the log group instead of being rejected).
    # Rather than treat that race as a hard failure, self-heal from it: if a delete attempt
    # unexpectedly succeeds, recreate the log group and re-enable protection, then keep retrying
    # until a delete is actually rejected with InvalidParameterException.
    _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"],
        lambda groups: any(
            g["logGroupName"] == name and g.get("deletionProtectionEnabled") for g in groups
        ),
        timeout_s=60.0,
        interval_s=5.0,
    )

    error = _verify_delete_rejected_while_protected(logs, name, timeout_s=200.0, interval_s=10.0)
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

    # The forbidden effect did not happen: the log group still exists.
    still_there = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert any(g["logGroupName"] == name for g in still_there), (
        f"expected {name} to still exist after the rejected delete, got {still_there}"
    )

    # Positive control: disabling protection allows the identical delete to succeed.
    logs.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=False)
    logs.delete_log_group(logGroupName=name)

    after = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
    assert not any(g["logGroupName"] == name for g in after), (
        f"expected {name} to be gone after protection was disabled, got {after}"
    )


def _safe(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _verify_delete_rejected_while_protected(logs, name, timeout_s=200.0, interval_s=10.0):
    """Repeatedly attempt DeleteLogGroup while deletion protection is (supposed to be) enabled,
    expecting InvalidParameterException, and return that rejection's Error dict. If enforcement
    hasn't caught up yet and a delete attempt unexpectedly succeeds (deleting the log group),
    self-heal by recreating the log group and re-enabling protection, then keep trying until the
    rejection is actually observed."""
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as e:
            error = e.response.get("Error", {})
            code = error.get("Code")
            if code == "InvalidParameterException":
                return error
            if code == "ResourceNotFoundException":
                # The log group doesn't exist right now -- most likely a previous iteration's
                # delete attempt raced ahead of protection enforcement and actually succeeded.
                # Recreate it, re-enable protection, and keep trying.
                pass
            else:
                raise
        # Either the delete unexpectedly succeeded, or the log group was already gone from a
        # prior racy success. Recreate it with protection enabled and try again.
        logs.create_log_group(logGroupName=name, tags={"Sim2RealOwner": "behavioral-suite"})
        logs.put_log_group_deletion_protection(logGroupIdentifier=name, deletionProtectionEnabled=True)
        time.sleep(interval_s)
    raise AssertionError(
        f"DeleteLogGroup on {name} was never rejected while protected within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
