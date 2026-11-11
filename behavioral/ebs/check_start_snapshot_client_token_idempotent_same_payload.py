"""start-snapshot-client-token-idempotent-same-payload."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-snapshot-client-token-idempotent-same-payload"
GROUP = "state"
SERVICES = ["ebs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-invoking StartSnapshot with the same ClientToken and identical payload is idempotent."""
    ebs = ctx.client("ebs")
    ec2 = ctx.client("ec2")
    token = ctx.unique_name("sim2real-ebs-tok-")
    description = ctx.unique_name("sim2real-ebs-idem-")
    tag_value = ctx.unique_name("sim2real-ebs-tagval-")

    first = ebs.start_snapshot(
        VolumeSize=1,
        Description=description,
        ClientToken=token,
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )
    snapshot_id = first["SnapshotId"]
    ctx.on_cleanup(lambda: _finalize_and_delete_snapshot(ctx, snapshot_id))

    second = ebs.start_snapshot(
        VolumeSize=1,
        Description=description,
        ClientToken=token,
        Tags=[{"Key": "sim2real-purpose", "Value": tag_value}],
    )

    assert second["SnapshotId"] == snapshot_id, (
        f"idempotent retry must return the original snapshot {snapshot_id}, got {second['SnapshotId']!r}"
    )
    assert second["Status"] == first["Status"], (
        f"idempotent retry must report the original status {first['Status']!r}, got {second['Status']!r}"
    )

    # Independent read through a different operation (EC2 DescribeSnapshots, not
    # the EBS StartSnapshot response) proves the retry did not create a second
    # snapshot: exactly one snapshot exists for this run's unique description.
    resp = ec2.describe_snapshots(Filters=[{"Name": "description", "Values": [description]}])
    matched = [s["SnapshotId"] for s in resp["Snapshots"]]
    assert matched == [snapshot_id], (
        f"expected exactly one snapshot {snapshot_id!r} for description {description!r}, found {matched}"
    )


# ===== helpers =====
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
