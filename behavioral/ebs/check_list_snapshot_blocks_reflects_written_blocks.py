"""list-snapshot-blocks-reflects-written-blocks."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-snapshot-blocks-reflects-written-blocks"
GROUP = "data-plane"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288
_INDICES = (0, 5, 10)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSnapshotBlocks enumerates exactly the block indices that were written, no more, no less."""
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1,
        Description=ctx.unique_name("sim2real-behav-ebs-listblocks-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-list-snapshot-blocks-reflects-written"}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    for idx in _INDICES:
        data = os.urandom(_BLOCK_SIZE)
        ebs.put_snapshot_block(
            SnapshotId=snapshot_id,
            BlockIndex=idx,
            BlockData=data,
            DataLength=len(data),
            Checksum=_sha256_b64(data),
            ChecksumAlgorithm="SHA256",
        )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=len(_INDICES))
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    returned_indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert returned_indices == set(_INDICES), f"expected {set(_INDICES)}, got {returned_indices}"
    assert listing["VolumeSize"] == 1, f"expected VolumeSize 1, got {listing['VolumeSize']}"
    assert listing["BlockSize"] == _BLOCK_SIZE, f"expected BlockSize {_BLOCK_SIZE}, got {listing['BlockSize']}"


# ===== helpers =====
def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=60.0, interval_s=3.0):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListSnapshotBlocks never found completed snapshot {snapshot_id}: {last_err}")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


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
