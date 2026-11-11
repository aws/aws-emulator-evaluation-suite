"""complete-snapshot-wrong-changed-blocks-count-is-accepted."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "complete-snapshot-wrong-changed-blocks-count-is-accepted"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CompleteSnapshot with a ChangedBlocksCount that mismatches the blocks written is accepted
    synchronously, but the snapshot then converges to 'error' rather than 'completed'."""
    ebs = ctx.client("ebs")
    tag_value = ctx.unique_name("sim2real-ebs-wrongcbc-")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": tag_value}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )

    # ChangedBlocksCount=5 deliberately mismatches the single block written.
    resp = ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=5)
    assert resp["Status"] in ("pending", "completed"), (
        f"CompleteSnapshot with a mismatched ChangedBlocksCount should not be rejected "
        f"synchronously (pending/completed), got {resp['Status']!r}"
    )

    # The mismatch is enforced asynchronously; reaching 'error' takes roughly 150s.
    final_state = _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=260.0)
    assert final_state == "error", (
        f"a mismatched ChangedBlocksCount is not validated synchronously but IS enforced "
        f"asynchronously: expected the snapshot to converge to 'error', got {final_state!r}"
    )


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _error_code_msg(fn):
    try:
        fn()
        return None, None
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")


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

