"""put-snapshot-block-response-returns-checksum-and-algorithm."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-snapshot-block-response-returns-checksum-and-algorithm"
GROUP = "data-plane"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """PutSnapshotBlock's echoed checksum and algorithm are honest, not just an unverified ack: an
    independent GetSnapshotBlock issued after completion reports the identical Checksum and
    ChecksumAlgorithm, and the identical bytes, that the mutating call had claimed."""
    ebs = ctx.client("ebs")
    started = ebs.start_snapshot(
        VolumeSize=1,
        Description=ctx.unique_name("sim2real-behav-ebs-checksum-"),
        Tags=[{"Key": "sim2real", "Value": "ebs-put-snapshot-block-checksum"}],
    )
    snapshot_id = started["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    checksum = _sha256_b64(data)
    put_resp = ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=data,
        DataLength=len(data),
        Checksum=checksum,
        ChecksumAlgorithm="SHA256",
    )
    assert put_resp["Checksum"] == checksum, (
        f"PutSnapshotBlock echoed Checksum {put_resp['Checksum']!r}, expected {checksum!r}"
    )
    assert put_resp["ChecksumAlgorithm"] == "SHA256", (
        f"PutSnapshotBlock echoed ChecksumAlgorithm {put_resp['ChecksumAlgorithm']!r}, expected 'SHA256'"
    )

    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    final_state = _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)
    assert final_state == "completed", (
        f"snapshot {snapshot_id} finished as {final_state!r}, expected 'completed'"
    )

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    blocks = {b["BlockIndex"]: b["BlockToken"] for b in listing["Blocks"]}
    assert 0 in blocks, f"expected block 0 in ListSnapshotBlocks, got {sorted(blocks)}"

    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=0, BlockToken=blocks[0])
    got_bytes = got["BlockData"].read()

    # The terminal assertions are an INDEPENDENT read (GetSnapshotBlock), not the PutSnapshotBlock
    # response asserted above — a target could ack a checksum it never actually validated or stored.
    assert got["Checksum"] == checksum, (
        f"independent GetSnapshotBlock reported Checksum {got['Checksum']!r}, expected {checksum!r} "
        f"(the value PutSnapshotBlock had echoed)"
    )
    assert got["ChecksumAlgorithm"] == "SHA256", (
        f"independent GetSnapshotBlock reported ChecksumAlgorithm {got['ChecksumAlgorithm']!r}, "
        f"expected 'SHA256'"
    )
    assert got_bytes == data, (
        f"block read back via GetSnapshotBlock ({len(got_bytes)} bytes) does not match the "
        f"{len(data)} bytes written"
    )


# ===== helpers =====
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
