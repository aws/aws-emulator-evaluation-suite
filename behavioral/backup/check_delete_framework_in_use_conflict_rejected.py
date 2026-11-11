"""delete-framework-in-use-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-framework-in-use-conflict-rejected"
GROUP = "error-semantics"
SERVICES = ["backup"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFramework called while the framework's asynchronous deployment is still in progress
    returns exactly ConflictException, leaves the framework intact, and a later delete (after the
    deployment settles) succeeds cleanly -- the positive control."""
    backup = ctx.client("backup")
    name = ctx.unique_name("sim2real_fw_conflict_").replace("-", "_")

    backup.create_framework(
        FrameworkName=name,
        FrameworkDescription="sim2real conflict-on-delete check",
        FrameworkControls=[
            {
                "ControlName": "BACKUP_RESOURCES_PROTECTED_BY_BACKUP_PLAN",
                "ControlScope": {
                    "ComplianceResourceTypes": ["RDS"],
                    "Tags": {"sim2real-delete-framework-conflict": name},
                },
            }
        ],
        FrameworkTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            backup.delete_framework(FrameworkName=name)

    ctx.on_cleanup(_cleanup)

    # Race the delete against the still-in-progress CREATE deployment. AWS Backup deploys the
    # framework's controls to AWS Config asynchronously after CreateFramework returns; a delete
    # issued into that window is rejected with ConflictException rather than proceeding.
    code, message = _error(lambda: backup.delete_framework(FrameworkName=name))
    assert code == "ConflictException", f"expected ConflictException deleting a framework with an in-progress deployment, got {code!r}"
    assert message == (
        f"Operation failed because of a concurrent update for the framework {name} in account "
        f"{ctx.account}. Try again later."
    ), f"actual_message={message!r}"

    # Effect absent: the framework must still exist.
    still_there = backup.describe_framework(FrameworkName=name)
    assert still_there["FrameworkName"] == name, f"framework {name} should still exist after the rejected delete, describe returned {still_there!r}"

    # Positive control: once the deployment has settled, deleting the very same framework succeeds.
    _poll_until(
        lambda: backup.describe_framework(FrameworkName=name),
        lambda r: r["DeploymentStatus"] not in ("CREATE_IN_PROGRESS",),
        timeout_s=120.0,
    )
    _delete_with_retry(backup, name)
    deleted["done"] = True

    code_after, message_after = _poll_framework_gone(backup, name, timeout_s=60.0)
    assert code_after == "ResourceNotFoundException", f"expected ResourceNotFoundException after the settled delete, got {code_after!r}"
    assert message_after == f"Framework {name} not found in account {ctx.account}.", f"actual_message={message_after!r}"


def _delete_with_retry(backup, name, retries=8, delay=10.0):
    from botocore.exceptions import ClientError

    last_exc = None
    for _ in range(retries):
        try:
            backup.delete_framework(FrameworkName=name)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException":
                raise
            last_exc = exc
            time.sleep(delay)
    raise last_exc


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_framework_gone(backup, name, timeout_s=60.0, interval_s=2.0):
    """Poll DescribeFramework until it is refused; return that (code, message), raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            backup.describe_framework(FrameworkName=name)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"framework {name} still describable after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
