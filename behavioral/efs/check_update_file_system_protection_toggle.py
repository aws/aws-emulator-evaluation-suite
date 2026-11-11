"""update-file-system-protection-toggle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-file-system-protection-toggle"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFileSystemProtection toggles ReplicationOverwriteProtection ENABLED<->DISABLED (default ENABLED)."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    fs_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    initial = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["FileSystemProtection"]
    assert initial["ReplicationOverwriteProtection"] == "ENABLED", (
        f"expected a freshly created file system to default ReplicationOverwriteProtection to "
        f"ENABLED, got {initial['ReplicationOverwriteProtection']!r}"
    )

    disabled = efs.update_file_system_protection(
        FileSystemId=fs_id, ReplicationOverwriteProtection="DISABLED"
    )
    assert disabled["ReplicationOverwriteProtection"] == "DISABLED", (
        f"expected UpdateFileSystemProtection to echo DISABLED, got {disabled['ReplicationOverwriteProtection']!r}"
    )
    after_disable = _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["FileSystemProtection"][
            "ReplicationOverwriteProtection"
        ],
        lambda s: s == "DISABLED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after_disable == "DISABLED", (
        f"expected an independent DescribeFileSystems read to observe DISABLED after the update, "
        f"got {after_disable!r}"
    )

    enabled = efs.update_file_system_protection(
        FileSystemId=fs_id, ReplicationOverwriteProtection="ENABLED"
    )
    assert enabled["ReplicationOverwriteProtection"] == "ENABLED", (
        f"expected UpdateFileSystemProtection to echo ENABLED, got {enabled['ReplicationOverwriteProtection']!r}"
    )
    after_enable = _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["FileSystemProtection"][
            "ReplicationOverwriteProtection"
        ],
        lambda s: s == "ENABLED",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after_enable == "ENABLED", (
        f"expected an independent DescribeFileSystems read to observe ENABLED after the second update, "
        f"got {after_enable!r}"
    )


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
