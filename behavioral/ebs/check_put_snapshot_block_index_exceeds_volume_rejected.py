"""put-snapshot-block-index-exceeds-volume-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-snapshot-block-index-exceeds-volume-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSnapshotBlock with a BlockIndex beyond the volume's block range is rejected, and the
    out-of-range block is never stored."""
    ebs = ctx.client("ebs")
    # VolumeSize=1 GiB => 1073741824 / 524288 = 2048 blocks, valid indices 0..2047
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-index-exceeds"}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    code, msg = _error_code_msg(lambda: ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=99999, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    ))
    assert code == "ValidationException", f"expected ValidationException, got code={code} msg={msg}"
    assert msg == "Block index 99999 is beyond the volume size extent", f"got msg={msg!r}"

    # positive control: an in-range index succeeds
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    final_state = _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)
    assert final_state == "completed", f"expected completed, got {final_state}"

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert indices == {0}, f"the out-of-range BlockIndex 99999 must never have persisted, got {indices}"


# ===== helpers =====
def _error_code_msg(fn):
    """Call fn(); return (Code, Message) from the ClientError it raises. An unexpected SUCCESS
    raises rather than returning a sentinel, so a target that accepts the request cannot read as
    a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"the call was expected to be rejected but SUCCEEDED, returning {result!r}")


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
