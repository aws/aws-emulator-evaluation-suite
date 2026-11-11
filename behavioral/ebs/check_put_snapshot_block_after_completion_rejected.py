"""put-snapshot-block-after-completion-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-snapshot-block-after-completion-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Writing a block to a snapshot that has already left the 'pending' state is rejected."""
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1,
        Tags=[{"Key": "sim2real-purpose", "Value": ctx.unique_name("put-snapshot-block-after-completion-")}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    control_data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=control_data, DataLength=len(control_data),
        Checksum=_sha256_b64(control_data), ChecksumAlgorithm="SHA256",
    )  # positive control: succeeds while snapshot is still pending
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    # Real AWS rejects this synchronously with ValidationException ("Snapshot is already
    # completed") once the write-path lockout has caught up with EC2's completed-state signal
    # (there can be a brief window right after completion where a write still slips through).
    code, msg = _put_block_until_rejected(ebs, snapshot_id, block_index=1)
    assert code == "ValidationException", f"expected ValidationException, got code={code} msg={msg}"
    assert msg == "Snapshot is already completed", f"got msg={msg!r}"

    # block 0 (written while still pending) must always be present regardless of what happened
    # with the transient block-1 write attempts above
    listing = ebs.list_snapshot_blocks(SnapshotId=snapshot_id)
    indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert 0 in indices, f"the control block written while pending must persist, got indices {indices}"


# ===== helpers =====
def _put_block_until_rejected(ebs, snapshot_id, block_index, timeout_s=90.0, interval_s=3.0):
    """Try PutSnapshotBlock repeatedly until it is rejected (or the bound expires), since the
    write-path lockout can trail EC2's completed-state signal briefly."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        data = os.urandom(_BLOCK_SIZE)
        try:
            ebs.put_snapshot_block(
                SnapshotId=snapshot_id, BlockIndex=block_index, BlockData=data, DataLength=len(data),
                Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
            )
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"PutSnapshotBlock on completed snapshot {snapshot_id} kept SUCCEEDING for {timeout_s}s"
    )


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
