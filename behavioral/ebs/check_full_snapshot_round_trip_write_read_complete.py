"""full-snapshot-round-trip-write-read-complete."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "full-snapshot-round-trip-write-read-complete"
GROUP = "data-plane"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288  # fixed EBS direct API block size (512 KiB)


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A block written via PutSnapshotBlock reads back byte-for-byte identical after completion."""
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1,
        Tags=[{"Key": "sim2real-purpose", "Value": ctx.unique_name("full-snapshot-round-trip-")}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    checksum = _sha256_b64(data)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=data,
        DataLength=len(data),
        Checksum=checksum,
        ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    final_state = _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)
    if final_state != "completed":
        ec2 = ctx.client("ec2")
        detail = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
        raise AssertionError(f"snapshot did not complete: state={final_state} detail={detail}")

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    blocks = {b["BlockIndex"]: b["BlockToken"] for b in listing["Blocks"]}
    assert 0 in blocks, f"expected block 0 in listing, got {list(blocks)}"

    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=0, BlockToken=blocks[0])
    got_bytes = got["BlockData"].read()

    assert got_bytes == data, "round-tripped block data does not match what was written"
    assert got["Checksum"] == checksum, f"expected checksum {checksum!r}, got {got['Checksum']!r}"
    assert got["ChecksumAlgorithm"] == "SHA256", (
        f"expected ChecksumAlgorithm SHA256, got {got['ChecksumAlgorithm']!r}"
    )
    assert got["DataLength"] == len(data), f"expected DataLength {len(data)}, got {got['DataLength']}"


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
