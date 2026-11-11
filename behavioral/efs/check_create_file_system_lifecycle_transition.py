"""create-file-system-lifecycle-transition."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-file-system-lifecycle-transition"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFileSystem starts a file system whose LifeCycleState eventually settles to 'available'."""
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-fs-")
    created = efs.create_file_system(
        CreationToken=token,
        PerformanceMode="generalPurpose",
        Tags=[{"Key": "Owner", "Value": "sim2real"}, {"Key": "Name", "Value": token}],
    )
    fs_id = created["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, fs_id))

    assert created["LifeCycleState"] in ("creating", "available"), (
        f"expected creating|available right after create, got {created['LifeCycleState']!r}"
    )
    assert created["CreationToken"] == token, (
        f"expected echoed CreationToken {token!r}, got {created['CreationToken']!r}"
    )
    assert created["NumberOfMountTargets"] == 0, (
        f"expected a freshly created file system to have 0 mount targets, got {created['NumberOfMountTargets']!r}"
    )

    final = _poll_until(
        lambda: efs.describe_file_systems(FileSystemId=fs_id)["FileSystems"][0],
        lambda fs: fs["LifeCycleState"] == "available",
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final["FileSystemId"] == fs_id, (
        f"expected the filtered describe to return {fs_id!r}, got {final.get('FileSystemId')!r}"
    )

    # The predicate above already pins final["LifeCycleState"] == "available" by construction, so it
    # proves nothing on its own. The unfiltered list is a genuinely independent read: a different
    # call shape (no FileSystemId filter) that can disagree with the by-id describe if the target's
    # list view lags or drops it.
    listed = _find_in_list(efs, fs_id)
    assert listed is not None, f"expected {fs_id} to appear in the unfiltered DescribeFileSystems list"
    assert listed["LifeCycleState"] == "available", (
        f"expected {fs_id} to read 'available' via the unfiltered list, got {listed['LifeCycleState']!r}"
    )


def _find_in_list(efs, fs_id):
    marker = None
    while True:
        kwargs = {"Marker": marker} if marker else {}
        page = efs.describe_file_systems(**kwargs)
        for fs in page["FileSystems"]:
            if fs["FileSystemId"] == fs_id:
                return fs
        marker = page.get("NextMarker")
        if not marker:
            return None


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
