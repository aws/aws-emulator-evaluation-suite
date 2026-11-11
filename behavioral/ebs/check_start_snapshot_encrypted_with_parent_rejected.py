"""start-snapshot-encrypted-with-parent-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-encrypted-with-parent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSnapshot rejects the mutually-exclusive combination of Encrypted and ParentSnapshotId."""
    ebs = ctx.client("ebs")

    parent_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-encrypted-parent"}]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, parent_id))
    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=parent_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=parent_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, parent_id, {"completed", "error"}, timeout_s=150.0)

    code, msg = _error_code_msg(lambda: ebs.start_snapshot(
        VolumeSize=1, ParentSnapshotId=parent_id, Encrypted=True
    ))
    assert code == "ValidationException", f"expected ValidationException, got code={code} msg={msg}"
    expected_msg = "ParentSnapshotId and Encrypt cannot be specified together"
    assert msg == expected_msg, f"ValidationException message: {msg!r}, expected {expected_msg!r}"

    # positive control: ParentSnapshotId alone (without Encrypted) is accepted
    child = _start_snapshot_with_retry(
        ebs, VolumeSize=1, ParentSnapshotId=parent_id,
        Tags=[{"Key": "sim2real", "Value": "ebs-behav-encrypted-parent-child"}],
    )
    child_id = child["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, child_id))
    assert child["Status"] == "pending", f"expected Status=pending, got {child['Status']!r}"
    assert child["ParentSnapshotId"] == parent_id, (
        f"expected ParentSnapshotId={parent_id!r}, got {child.get('ParentSnapshotId')!r}"
    )


# ===== helpers =====
def _error_code_msg(fn):
    """Return (Error.Code, Error.Message) of the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _start_snapshot_with_retry(ebs, timeout_s=60.0, interval_s=3.0, **kwargs):
    """StartSnapshot with a just-completed ParentSnapshotId can transiently see it as 'not complete'
    while EC2's completed-state signal outpaces the EBS direct-API backend; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.start_snapshot(**kwargs)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ValidationException" or "not complete" not in str(
                e.response["Error"].get("Message", "")
            ):
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"StartSnapshot never accepted parent as complete: {last_err}")


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

