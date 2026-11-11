"""update-file-system-throughput-mode-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-file-system-throughput-mode-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFileSystem changes ThroughputMode and settles back to 'available' with the new value persisted."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    created = efs.create_file_system(
        CreationToken=token,
        ThroughputMode="bursting",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    fs_id = created["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")
    initial_mode = efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0]["ThroughputMode"]
    assert initial_mode == "bursting", f"expected initial ThroughputMode bursting, got {initial_mode!r}"

    efs.update_file_system(FileSystemId=fs_id, ThroughputMode="provisioned", ProvisionedThroughputInMibps=1.0)

    final = _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0],
        lambda fs: fs["LifeCycleState"] == "available" and fs["ThroughputMode"] == "provisioned",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["ThroughputMode"] == "provisioned", f"expected ThroughputMode provisioned, got {final['ThroughputMode']!r}"
    assert final["ProvisionedThroughputInMibps"] == 1.0, (
        f"expected ProvisionedThroughputInMibps 1.0 persisted, got {final['ProvisionedThroughputInMibps']!r}"
    )
    assert final["LifeCycleState"] == "available", f"expected LifeCycleState available, got {final['LifeCycleState']!r}"


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
