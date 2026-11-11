"""get-snapshot-block-invalid-token-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-snapshot-block-invalid-token-rejected"
GROUP = "error-semantics"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetSnapshotBlock with a malformed BlockToken is rejected with ValidationException."""
    ebs = ctx.client("ebs")
    tag_value = ctx.unique_name("sim2real-ebs-badtok-")
    snapshot_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))

    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)

    listing = _list_blocks_with_retry(ebs, snapshot_id)
    real_token = {b["BlockIndex"]: b["BlockToken"] for b in listing["Blocks"]}[0]

    refused = _client_error(lambda: ebs.get_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockToken="not-a-real-token=="
    ))
    code = refused.response["Error"]["Code"]
    assert code == "ValidationException", (
        f"GetSnapshotBlock with a malformed BlockToken answered {code!r}, expected "
        f"ValidationException"
    )
    message = refused.response["Error"].get("Message")
    assert message == "The block token not-a-real-token== is invalid.", (
        f"GetSnapshotBlock with a malformed BlockToken answered message {message!r}"
    )

    # positive control: the real token from ListSnapshotBlocks works
    got = ebs.get_snapshot_block(SnapshotId=snapshot_id, BlockIndex=0, BlockToken=real_token)
    got_data = got["BlockData"].read()
    assert got_data == data, (
        f"reading block 0 with the token ListSnapshotBlocks issued returned "
        f"{len(got_data)} bytes that did not match the {len(data)} written bytes"
    )


# ===== helpers =====
def _client_error(fn) -> ClientError:
    """Call fn(); return the ClientError it raises, so the caller can read its Code.

    Raises on an unexpected SUCCESS rather than returning a falsy sentinel: an emulator that
    serves a block for a token it never issued must not turn that acceptance into a mere
    code mismatch.
    """
    try:
        fn()
    except ClientError as e:
        return e
    raise AssertionError("the call SUCCEEDED where real AWS rejects it")


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


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
