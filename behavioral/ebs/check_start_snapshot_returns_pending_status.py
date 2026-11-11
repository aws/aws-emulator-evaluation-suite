"""start-snapshot-returns-pending-status."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-returns-pending-status"
GROUP = "state"
SERVICES = ["ebs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartSnapshot creates a new snapshot in the 'pending' state with a well-formed id,
    corroborated by an independent EC2 DescribeSnapshots read once the id is visible."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    tag_value = ctx.unique_name("sim2real-ebs-tagval-")
    resp = ebs.start_snapshot(VolumeSize=1, Tags=[{"Key": "sim2real-purpose", "Value": tag_value}])
    snapshot_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))

    assert resp["Status"] == "pending", f"expected pending, got {resp['Status']}"
    assert re.match(r"^snap-[0-9a-f]+$", snapshot_id), snapshot_id
    assert resp["VolumeSize"] == 1, f"expected VolumeSize 1, got {resp['VolumeSize']}"
    assert resp["OwnerId"], f"expected non-empty OwnerId, got {resp['OwnerId']!r}"

    described = _describe_snapshot(ctx, ec2, snapshot_id)
    assert described["State"] == "pending", (
        f"independent EC2 read expected State pending, got {described['State']}"
    )
    assert described["VolumeSize"] == 1, (
        f"independent EC2 read expected VolumeSize 1, got {described['VolumeSize']}"
    )
    assert described["OwnerId"] == resp["OwnerId"], (
        f"EC2 read OwnerId {described['OwnerId']} != StartSnapshot OwnerId {resp['OwnerId']}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _describe_snapshot(ctx, ec2, snapshot_id, cap_s=60.0):
    """DescribeSnapshots, retried while the new id has not yet propagated to EC2."""
    start = time.monotonic()
    budget_s = _budget_s(ctx, cap_s)
    deadline = start + budget_s
    while True:
        try:
            return ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise
            if time.monotonic() >= deadline:
                if budget_s < cap_s:
                    raise TimeoutError(
                        f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
                        f"{cap_s}s wait ended with {snapshot_id} not yet visible; not graded"
                    )
                raise AssertionError(f"snapshot {snapshot_id} never became visible to DescribeSnapshots: {e}")
        time.sleep(2.0)


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
