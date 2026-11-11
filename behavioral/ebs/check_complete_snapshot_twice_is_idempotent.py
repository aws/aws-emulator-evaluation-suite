"""complete-snapshot-twice-is-idempotent."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-snapshot-twice-is-idempotent"
GROUP = "state"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteSnapshot is idempotent: empirically AWS does not reject a repeat completion call
    on an already-completed snapshot; the call succeeds and the underlying state/blocks are
    unchanged (no corruption, no duplicate side effects)."""
    ebs = ctx.client("ebs")

    snapshot_a = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": ctx.unique_name("complete-snapshot-twice-")}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_a))
    data_a = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_a, BlockIndex=0, BlockData=data_a, DataLength=len(data_a),
        Checksum=_sha256_b64(data_a), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_a, ChangedBlocksCount=1)
    state_a = _wait_for_snapshot_state(ctx, snapshot_a, {"completed", "error"}, timeout_s=150.0)
    assert state_a == "completed", f"expected snapshot {snapshot_a} to reach completed, got {state_a}"

    # repeat call: must not raise, and must report a terminal status (not silently corrupt state)
    second = ebs.complete_snapshot(SnapshotId=snapshot_a, ChangedBlocksCount=1)
    assert second["Status"] in ("completed", "pending"), f"unexpected Status on repeat call: {second['Status']}"

    # the underlying snapshot must still be exactly "completed" with the original block intact
    final_state = _wait_for_snapshot_state(ctx, snapshot_a, {"completed", "error"}, timeout_s=60.0)
    assert final_state == "completed", f"expected snapshot {snapshot_a} to remain completed after repeat call, got {final_state}"
    listing = _list_blocks_with_retry(ebs, snapshot_a)
    got_indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert got_indices == {0}, f"expected block indices {{0}} after repeat completion, got {got_indices}"


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
