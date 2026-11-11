"""replication-configuration-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "replication-configuration-lifecycle"
GROUP = "state"
SERVICES = ["efs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateReplicationConfiguration takes the destination from ENABLING to ENABLED, and
    DeleteReplicationConfiguration moves it out of ENABLED (DELETING or gone).
    """
    efs = ctx.client("efs")
    token = ctx.unique_name("sim2real-efs-src-")
    src_id = efs.create_file_system(
        CreationToken=token, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )["FileSystemId"]
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, src_id))
    _wait_fs_state(efs, src_id, "available")

    created = efs.create_replication_configuration(
        SourceFileSystemId=src_id, Destinations=[{"Region": ctx.region}]
    )
    dest = created["Destinations"][0]
    assert dest["Status"] in ("ENABLING", "ENABLED"), (
        f"unexpected destination status {dest['Status']!r}"
    )
    dest_id = dest["FileSystemId"]
    _tag_resource_best_effort(efs, dest_id)
    ctx.on_cleanup(lambda: _delete_fs_best_effort(efs, dest_id))
    ctx.on_cleanup(lambda: _delete_replication_best_effort(efs, src_id))

    final_status = _poll_until(
        lambda: efs.describe_replication_configurations(FileSystemId=src_id)["Replications"][0][
            "Destinations"
        ][0]["Status"],
        lambda s: s == "ENABLED",
        timeout_s=150.0,
        interval_s=10.0,
    )
    assert final_status == "ENABLED", f"expected ENABLED, got {final_status!r}"

    # the replication status word alone is not proof a second file system exists; an
    # independent read at the destination confirms the consequence, not just the label.
    dest_fs = efs.describe_file_systems(FileSystemId=dest_id)["FileSystems"][0]
    assert dest_fs["FileSystemId"] == dest_id, (
        f"destination file system {dest_id!r} not visible via describe_file_systems"
    )

    efs.delete_replication_configuration(SourceFileSystemId=src_id)

    # deletion is asynchronous: confirm the replication left the ENABLED state (either a
    # transient DELETING status, or it has already fully disappeared) without blocking on
    # the full multi-minute teardown of the destination file system.
    post_delete = _poll_until(
        lambda: _replication_status(efs, src_id),
        lambda s: s in ("DELETING", "gone"),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert post_delete in ("DELETING", "gone"), f"expected DELETING or gone, got {post_delete!r}"


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


def _tag_resource_best_effort(efs, resource_id):
    try:
        efs.tag_resource(ResourceId=resource_id, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    except Exception:
        pass


def _replication_status(efs, src_id):
    """The first destination's Status, or "gone" once DescribeReplicationConfigurations 404s."""
    try:
        resp = efs.describe_replication_configurations(FileSystemId=src_id)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ReplicationNotFound":
            return "gone"
        raise
    return resp["Replications"][0]["Destinations"][0]["Status"]


def _delete_replication_best_effort(efs, src_id):
    try:
        efs.delete_replication_configuration(SourceFileSystemId=src_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("FileSystemNotFound", "ReplicationNotFound"):
            raise
    deadline = time.monotonic() + 600.0
    while time.monotonic() < deadline:
        try:
            if _replication_status(efs, src_id) == "gone":
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("FileSystemNotFound", "ReplicationNotFound"):
                raise
        time.sleep(10.0)


def _delete_fs_best_effort(efs, fs_id):
    try:
        efs.delete_file_system(FileSystemId=fs_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "FileSystemNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
