"""put-snapshot-block-checksum-mismatch-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-snapshot-block-checksum-mismatch-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutSnapshotBlock with a Checksum that doesn't match the sent data is rejected and the block is not stored."""
    ebs = ctx.client("ebs")
    tag_value = ctx.unique_name("sim2real-ebs-tagval-")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    wrong_checksum = _sha256_b64(os.urandom(_BLOCK_SIZE))  # checksum of different bytes

    code, msg = _error_code_msg(lambda: ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=wrong_checksum, ChecksumAlgorithm="SHA256",
    ))
    # Empirically AWS rejects a checksum that doesn't match the transmitted bytes as a
    # signing-integrity failure (the checksum is part of the SigV4 signing process), not a
    # ValidationException.
    assert code == "InvalidSignatureException", f"expected InvalidSignatureException, got code={code} msg={msg}"
    assert msg == (
        f"The value passed in as x-amz-Checksum does not match the computed checksum. "
        f"Computed checksum: {_sha256_b64(data)} expected checksum: {wrong_checksum}"
    ), f"got msg={msg!r}"

    # positive control: a block with a correct checksum at a different index succeeds
    good_data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=1, BlockData=good_data, DataLength=len(good_data),
        Checksum=_sha256_b64(good_data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    indices = {b["BlockIndex"] for b in listing["Blocks"]}
    assert indices == {1}, f"the checksum-mismatched block must not have persisted, got {indices}"


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


def _list_blocks_with_retry(ebs, snapshot_id, timeout_s=180.0, interval_s=3.0):
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
