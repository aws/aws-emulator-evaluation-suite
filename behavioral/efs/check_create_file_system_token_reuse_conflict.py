"""create-file-system-token-reuse-conflict."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-file-system-token-reuse-conflict"
GROUP = "idempotency"
SERVICES = ["efs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-using a CreationToken after the file system exists returns FileSystemAlreadyExists, not a
    duplicate. The token is a per-file-system reservation, not a permanent lock: once the original
    file system is deleted, the identical CreationToken is free to succeed again."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    resource_tags = [{"Key": "sim2real-check", "Value": CHECK}]

    fs_id = efs.create_file_system(CreationToken=token, Tags=resource_tags)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))
    _wait_fs_state(efs, fs_id, "available")

    try:
        efs.create_file_system(CreationToken=token, Tags=resource_tags)
        raise AssertionError("expected FileSystemAlreadyExists on CreationToken reuse")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "FileSystemAlreadyExists", f"expected FileSystemAlreadyExists, got {code!r}"
        msg = e.response["Error"].get("Message")
        expected_msg = f"File system '{fs_id}' already exists with creation token '{token}'"
        assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"
        referenced_id = e.response.get("FileSystemId")
        assert referenced_id == fs_id, f"expected FileSystemId {fs_id!r} on the error, got {referenced_id!r}"

    # effect absent: no duplicate file system was created for this creation token
    matches = efs.describe_file_systems(CreationToken=token)["FileSystems"]
    assert len(matches) == 1, f"expected exactly 1 file system for token {token!r}, got {len(matches)}"
    assert matches[0]["FileSystemId"] == fs_id, (
        f"expected the sole match to be {fs_id!r}, got {matches[0]['FileSystemId']!r}"
    )

    # positive control: a fresh, different token succeeds normally
    other_token = ctx.unique_name("sim2real-efs-fs-other-")
    other_id = efs.create_file_system(CreationToken=other_token, Tags=resource_tags)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, other_id))
    assert other_id != fs_id, f"expected a different FileSystemId for a different token, got {fs_id!r} again"

    # restore: once the original file system is gone, the identical token is no longer reserved
    efs.delete_file_system(FileSystemId=fs_id)
    _wait_fs_deleted(efs, fs_id)
    restored_id = efs.create_file_system(CreationToken=token, Tags=resource_tags)["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, restored_id))
    assert restored_id != fs_id, f"expected a fresh FileSystemId on token reuse after delete, got the stale {fs_id!r}"

    # terminal read, independent of the mutating call: the reused token now resolves to the restored fs
    restored_matches = efs.describe_file_systems(CreationToken=token)["FileSystems"]
    assert len(restored_matches) == 1, (
        f"expected exactly 1 file system for token {token!r} after restore, got {len(restored_matches)}"
    )
    assert restored_matches[0]["FileSystemId"] == restored_id, (
        f"expected the restored match to be {restored_id!r}, got {restored_matches[0]['FileSystemId']!r}"
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


def _wait_fs_deleted(efs, fs_id, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            efs.describe_file_systems(FileSystemId=fs_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "FileSystemNotFound":
                return
            raise
        time.sleep(5.0)
    raise AssertionError(f"file system {fs_id} not deleted within {timeout_s}s")


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
