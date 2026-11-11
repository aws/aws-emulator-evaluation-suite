"""start-snapshot-nonexistent-parent-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-nonexistent-parent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ebs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartSnapshot with a ParentSnapshotId that does not exist is rejected with ResourceNotFoundException."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")

    # A syntactically-fabricated ID (e.g. all-sequential hex) can fail AWS's internal ID-format
    # validation with ValidationException before the not-found check ever runs. To exercise the
    # true "parent does not exist" boundary we need an ID that is guaranteed well-formed: create
    # a real snapshot, delete it, and use its now-absent (but validly-shaped) ID as the parent.
    throwaway_id = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-throwaway-parent"}]
    )["SnapshotId"]
    _finalize_and_delete_snapshot(ctx, throwaway_id)

    # Deletion can itself lag propagation to the EBS direct-API backend (mirroring the
    # completion lag seen elsewhere): immediately after delete, the backend may still answer
    # "not complete" for a few seconds before it reports the snapshot as gone. Poll through that
    # transient state to the true not-found boundary.
    code, msg = _start_snapshot_expect_not_found(ebs, throwaway_id)
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got code={code} msg={msg}"
    expected_msg = f"The snapshot '{throwaway_id}' does not exist."
    assert msg == expected_msg, f"ResourceNotFoundException message: {msg!r}, expected {expected_msg!r}"

    # positive control: StartSnapshot without a bogus parent still succeeds
    resp = ebs.start_snapshot(
        VolumeSize=1, Tags=[{"Key": "sim2real", "Value": "ebs-behav-control-parent"}]
    )
    snapshot_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))
    assert resp["Status"] == "pending", f"expected Status=pending on create, got {resp['Status']!r}"

    # independent read at the destination: EC2's own view agrees the control snapshot exists and
    # is not stuck in the error state a real ResourceNotFoundException-triggering target might fall
    # back to.
    described = ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
    assert described["State"] in ("pending", "completed"), (
        f"expected DescribeSnapshots to independently report {snapshot_id} as pending/completed, "
        f"got State={described['State']!r}"
    )


# ===== helpers =====
def _start_snapshot_expect_not_found(ebs, parent_id, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_code, last_msg = None, None
    while time.monotonic() < deadline:
        try:
            result = ebs.start_snapshot(VolumeSize=1, ParentSnapshotId=parent_id)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message")
            if code == "ValidationException" and "not complete" in str(msg):
                last_code, last_msg = code, msg
                time.sleep(interval_s)
                continue
            return code, msg
        raise AssertionError(
            f"StartSnapshot with deleted parent {parent_id} succeeded: {result!r}"
        )
    return last_code, last_msg


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

