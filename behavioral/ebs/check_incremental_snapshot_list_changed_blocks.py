"""incremental-snapshot-list-changed-blocks."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "incremental-snapshot-list-changed-blocks"
GROUP = "data-plane"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListChangedBlocks between a parent and an incremental child reports only the block that differs."""
    ebs = ctx.client("ebs")

    parent_id = ebs.start_snapshot(
        VolumeSize=1,
        Description=ctx.unique_name("sim2real-behav-ebs-icb-parent-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-behav-incremental-cb-parent"}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, parent_id))

    data0 = os.urandom(_BLOCK_SIZE)
    data1_parent = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=parent_id, BlockIndex=0, BlockData=data0, DataLength=len(data0),
        Checksum=_sha256_b64(data0), ChecksumAlgorithm="SHA256",
    )
    ebs.put_snapshot_block(
        SnapshotId=parent_id, BlockIndex=1, BlockData=data1_parent, DataLength=len(data1_parent),
        Checksum=_sha256_b64(data1_parent), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=parent_id, ChangedBlocksCount=2)
    _wait_for_snapshot_state(ctx, parent_id, {"completed", "error"}, timeout_s=150.0)

    child_id = _start_snapshot_with_retry(
        ebs,
        VolumeSize=1,
        ParentSnapshotId=parent_id,
        Description=ctx.unique_name("sim2real-behav-ebs-icb-child-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-behav-incremental-cb-child"}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, child_id))

    data1_child = os.urandom(_BLOCK_SIZE)  # only block 1 changes; block 0 is inherited unchanged
    ebs.put_snapshot_block(
        SnapshotId=child_id, BlockIndex=1, BlockData=data1_child, DataLength=len(data1_child),
        Checksum=_sha256_b64(data1_child), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=child_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, child_id, {"completed", "error"}, timeout_s=150.0)

    diff = _list_changed_blocks_with_retry(ebs, parent_id, child_id)
    changed_indices = {b["BlockIndex"] for b in diff["ChangedBlocks"]}
    assert changed_indices == {1}, f"expected only block 1 changed, got {changed_indices}"


# ===== helpers =====
def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _list_changed_blocks_with_retry(ebs, first_id, second_id, timeout_s=150.0, interval_s=3.0):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.list_changed_blocks(FirstSnapshotId=first_id, SecondSnapshotId=second_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListChangedBlocks never found completed snapshots {first_id},{second_id}: {last_err}")


def _start_snapshot_with_retry(ebs, timeout_s=60.0, interval_s=3.0, **kwargs):
    """StartSnapshot with a just-completed ParentSnapshotId can transiently see it as 'not complete'
    while EC2's completed-state signal outpaces the EBS direct-API backend; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.start_snapshot(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException" or "not complete" not in str(
                e.response["Error"].get("Message", "")
            ):
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"StartSnapshot never accepted parent as complete: {last_err}")


def _wait_for_snapshot_state(ctx, snapshot_id, states, timeout_s=120.0, interval_s=3.0):
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id])
            last = resp["Snapshots"][0]["State"]
            if last in states:
                return last
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
        time.sleep(interval_s)
    raise AssertionError(f"snapshot {snapshot_id} never reached {states} (last={last})")


def _delete_snapshot(ctx, snapshot_id):
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

