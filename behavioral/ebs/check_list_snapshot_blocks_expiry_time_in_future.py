"""list-snapshot-blocks-expiry-time-in-future."""
from __future__ import annotations

import base64
import hashlib
import os
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-snapshot-blocks-expiry-time-in-future"
GROUP = "state"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288
_SANITY_CEILING_DAYS = 30


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSnapshotBlocks returns an ExpiryTime for the block-token session that is in the future."""
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-list-blocks-expiry"}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))

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

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    now = datetime.now(timezone.utc)
    expiry = listing["ExpiryTime"]
    assert expiry > now, f"ExpiryTime {expiry} is not in the future (now={now})"
    # The API reference documents no fixed TTL for the BlockToken, and the expiry offset is not
    # stable between calls.
    # _SANITY_CEILING_DAYS is a generous ceiling, not the real duration: it only catches a target
    # that never expires the token (e.g. echoes a far-future sentinel) rather than pinning AWS's
    # actual, apparently-variable window.
    ceiling = now + timedelta(days=_SANITY_CEILING_DAYS)
    assert expiry < ceiling, f"ExpiryTime {expiry} is implausibly far out (ceiling={ceiling})"


# ===== helpers =====
def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=120.0, interval_s=3.0):
    """The EBS direct-API data plane can lag EC2's completed-state signal; poll through it for up to 120s."""
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
