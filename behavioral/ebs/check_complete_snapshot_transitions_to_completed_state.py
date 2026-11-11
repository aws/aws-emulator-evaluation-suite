"""complete-snapshot-transitions-to-completed-state."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-snapshot-transitions-to-completed-state"
GROUP = "state"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288  # fixed EBS direct API block size (512 KiB)


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pending snapshot with all its blocks written transitions to 'completed' after CompleteSnapshot."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    tag_value = ctx.unique_name("sim2real-ebs-complete-")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1,
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
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
    complete_resp = ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    assert complete_resp["Status"] in ("pending", "completed"), (
        f"expected Status pending|completed on CompleteSnapshot, got {complete_resp['Status']!r}"
    )

    final_state = _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)
    assert final_state == "completed", f"expected snapshot {snapshot_id} state completed, got {final_state!r}"

    described = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    assert described["Progress"] == "100%", (
        f"expected Progress '100%' for completed snapshot {snapshot_id}, got {described['Progress']!r}"
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
