"""list-changed-blocks-unrelated-snapshots-rejected."""
from __future__ import annotations

import base64
import hashlib
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-changed-blocks-unrelated-snapshots-rejected"
GROUP = "overly-permissive"
SERVICES = ["ebs"]

_BLOCK_SIZE = 524288
_TAGS = [{"Key": "sim2real", "Value": "ebs-behav-list-changed-blocks-unrelated"}]


@tags("axis:rejection", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListChangedBlocks between two snapshots that share no lineage is rejected (isolation boundary)."""
    ebs = ctx.client("ebs")

    snapshot_a = _make_completed_snapshot(ctx)
    snapshot_b = _make_completed_snapshot(ctx)

    code, msg = _error_code_msg(lambda: ebs.list_changed_blocks(FirstSnapshotId=snapshot_a, SecondSnapshotId=snapshot_b))
    # Empirically AWS reports unrelated-lineage snapshots as a ValidationException ("... are not
    # related"), not ResourceNotFoundException as the API reference's Reason enum implies.
    assert code == "ValidationException", f"expected ValidationException, got code={code} msg={msg}"
    assert msg == f"The snapshot {snapshot_a} and {snapshot_b} are not related.", f"got msg={msg!r}"

    # positive control: comparing a snapshot against its own incremental child (true lineage) succeeds
    child_id = _start_snapshot_with_retry(
        ebs, VolumeSize=1, ParentSnapshotId=snapshot_a, Tags=_TAGS
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, child_id))
    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=child_id, BlockIndex=1, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=child_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, child_id, {"completed", "error"}, timeout_s=150.0)

    diff = _list_changed_blocks_with_retry(ebs, snapshot_a, child_id)
    changed_indices = {b["BlockIndex"] for b in diff["ChangedBlocks"]}
    assert changed_indices == {1}, (
        f"expected only the newly written block 1 to differ from its unrelated-lineage-rejected "
        f"parent, got {changed_indices}"
    )


# ===== helpers =====
def _make_completed_snapshot(ctx):
    ebs = ctx.client("ebs")
    snapshot_id = ebs.start_snapshot(VolumeSize=1, Tags=_TAGS)["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snapshot_id))
    data = os.urandom(_BLOCK_SIZE)
    ebs.put_snapshot_block(
        SnapshotId=snapshot_id, BlockIndex=0, BlockData=data, DataLength=len(data),
        Checksum=_sha256_b64(data), ChecksumAlgorithm="SHA256",
    )
    ebs.complete_snapshot(SnapshotId=snapshot_id, ChangedBlocksCount=1)
    _wait_for_snapshot_state(ctx, snapshot_id, {"completed", "error"}, timeout_s=150.0)
    _list_blocks_with_retry(ebs, snapshot_id)  # ensure the EBS direct-API backend has caught up
    return snapshot_id


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


def _list_changed_blocks_with_retry(ebs, first_id, second_id, timeout_s=180.0, interval_s=3.0):
    """The EBS direct-API data plane can lag EC2's completed-state signal briefly; poll through it."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return ebs.list_changed_blocks(FirstSnapshotId=first_id, SecondSnapshotId=second_id)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"ListChangedBlocks never found completed snapshots {first_id},{second_id}: {last_err}")


def _error_code_msg(fn):
    """Call fn(); return (Code, Message) from the ClientError it raises. An unexpected SUCCESS
    raises rather than returning a sentinel, so an over-permissive target that allows unrelated
    lineage cannot be reported as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects ListChangedBlocks between unrelated-lineage snapshots, but it "
        f"SUCCEEDED and returned {result!r}"
    )


def _sha256_b64(data: bytes) -> str:
    return base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")


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

