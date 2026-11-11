"""concurrent-put-snapshot-block-distinct-indices."""
from __future__ import annotations

import base64
import hashlib
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-snapshot-block-distinct-indices"
GROUP = "concurrency"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288
_INDICES = tuple(range(8))


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutSnapshotBlock calls at distinct indices all persist durably with no cross-write corruption."""
    ebs = ctx.client("ebs")
    tag_value = ctx.unique_name("sim2real-ebs-concurrent-blocks-")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    written = {idx: os.urandom(_BLOCK_SIZE) for idx in _INDICES}

    def _write(idx):
        data = written[idx]
        ebs.put_snapshot_block(
            SnapshotId=snapshot_id, BlockIndex=idx, BlockData=data, DataLength=len(data),
            Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
        )
        return idx

    with ThreadPoolExecutor(max_workers=len(_INDICES)) as pool:
        futures = [pool.submit(_write, idx) for idx in _INDICES]
        completed = {f.result() for f in as_completed(futures)}
    assert completed == set(_INDICES), f"not all concurrent writes completed: {completed}"

    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=len(_INDICES))
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    listing = _list_blocks_with_retry(ebs, snapshot_id, max_results=100)
    tokens = {b["BlockIndex"]: b["BlockToken"] for b in listing["Blocks"]}
    assert set(tokens) == set(_INDICES), f"expected {set(_INDICES)}, got {set(tokens)}"

    for idx in _INDICES:
        got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=idx, BlockToken=tokens[idx])
        assert got["BlockData"].read() == written[idx], f"block {idx} data does not match what was written"


# ===== helpers =====
def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=60.0, interval_s=3.0, max_results=None):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    kwargs = {"MaxResults": max_results} if max_results else {}
    while time.monotonic() < deadline:
        try:
            return ebs.list_snapshot_blocks(SnapshotId=snapshot_id, **kwargs)
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
