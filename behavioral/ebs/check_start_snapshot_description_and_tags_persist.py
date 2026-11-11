"""start-snapshot-description-and-tags-persist."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-description-and-tags-persist"
GROUP = "state"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Description and Tags supplied at StartSnapshot persist through to the completed EC2 snapshot."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    description = "sim2real-behavioral-description"
    tag_value = ctx.unique_name("sim2real-ebs-tagval-")

    resp = ebs.start_snapshot(
        VolumeSize=1,
        Description=description,
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )
    snapshot_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))

    assert resp["Description"] == description, (
        f"StartSnapshot response Description mismatch: expected {description!r}, got {resp.get('Description')!r}"
    )

    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id,
        BlockIndex=0,
        BlockData=data,
        DataLength=len(data),
        Checksum=_sha256_b64(data),
        ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    described = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    assert described["Description"] == description, (
        f"DescribeSnapshots Description mismatch: expected {description!r}, got {described.get('Description')!r}"
    )
    tag_values = {t["Key"]: t["Value"] for t in described.get("Tags", [])}
    assert tag_values.get("sim2real-purpose") == tag_value, (
        f"DescribeSnapshots tag sim2real-purpose mismatch: expected {tag_value!r}, got {tag_values.get('sim2real-purpose')!r}"
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


def _finalize_and_delete_snapshot(ctx, snapshot_id, changed_blocks_count=0):
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    try:
        ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=changed_blocks_count)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    try:
        _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=120.0)
    except AssertionError:
        pass
    try:
        ec2.delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
