"""backup-policy-status-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "backup-policy-status-transitions"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBackupPolicy drives BackupPolicy.Status through ENABLING->ENABLED and DISABLING->DISABLED."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(CreationToken=token, Tags=[{"Key": "Owner", "Value": "sim2real"}])["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    # A freshly created file system has never had a backup policy set: EFS raises
    # PolicyNotFound rather than returning a synthesized DISABLED status.
    initial_code, initial_msg = _client_error(lambda: efs.describe_backup_policy(FileSystemId=fs_id))
    assert initial_code == "PolicyNotFound", f"expected PolicyNotFound, got {initial_code!r}"
    expected_msg = None  # AWS sends this error with no Message member
    assert initial_msg == expected_msg, f"expected message {expected_msg!r}, got {initial_msg!r}"

    enable_resp = efs.put_backup_policy(FileSystemId=fs_id, BackupPolicy={"Status": "ENABLED"})
    enable_status = enable_resp["BackupPolicy"]["Status"]
    assert enable_status in ("ENABLING", "ENABLED"), f"expected ENABLING or ENABLED, got {enable_status!r}"

    enabled = _poll_until(
        lambda: efs.describe_backup_policy(FileSystemId=fs_id)["BackupPolicy"]["Status"],
        lambda s: s == "ENABLED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert enabled == "ENABLED", f"expected ENABLED, got {enabled!r}"

    disable_resp = efs.put_backup_policy(FileSystemId=fs_id, BackupPolicy={"Status": "DISABLED"})
    disable_status = disable_resp["BackupPolicy"]["Status"]
    assert disable_status in ("DISABLING", "DISABLED"), f"expected DISABLING or DISABLED, got {disable_status!r}"

    disabled = _poll_until(
        lambda: efs.describe_backup_policy(FileSystemId=fs_id)["BackupPolicy"]["Status"],
        lambda s: s == "DISABLED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert disabled == "DISABLED", f"expected DISABLED, got {disabled!r}"


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_fs_state(efs, fs_id, state, timeout_s=180.0):
    return _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["LifeCycleState"],
        lambda s: s == state,
        timeout_s=timeout_s,
        interval_s=5.0,
    )


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
