"""op-contract-modify-snapshot-tier."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-snapshot-tier"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifySnapshotTier: requesting an archive transition is accepted (tieringStartTime
    is set and DescribeSnapshotTierStatus reflects the archival-in-progress status), and a
    nonexistent snapshot id is rejected."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-tier-")
    volume = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3", TagSpecifications=[_tag_spec("volume", name)]
    )
    volume_id = volume["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snapshot = ec2.create_snapshot(VolumeId=volume_id, TagSpecifications=[_tag_spec("snapshot", name)])
    snapshot_id = snapshot["SnapshotId"]
    ctx.on_cleanup(lambda: _best_effort_delete_snapshot(ctx, snapshot_id))
    ec2.get_waiter("snapshot_completed").wait(
        SnapshotIds=[snapshot_id], WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    # success path: the archive request is accepted immediately (full archival can take
    # much longer on real AWS, so we assert acceptance + status, not full completion)
    resp = ec2.modify_snapshot_tier(SnapshotId=snapshot_id, StorageTier="archive")
    assert resp["SnapshotId"] == snapshot_id, resp
    assert "TieringStartTime" in resp, resp

    status = ec2.describe_snapshot_tier_status(
        Filters=[{"Name": "snapshot-id", "Values": [snapshot_id]}]
    )["SnapshotTierStatuses"]
    assert status, "expected a tier status entry for the snapshot"
    # Full archival can take hours on real AWS, so immediately after the request the
    # StorageTier field still reads "standard"; the observable async effect is that
    # LastTieringOperationStatus flips to "archival-in-progress" (or has already
    # completed if AWS was extremely fast).
    assert status[0]["LastTieringOperationStatus"] in (
        "archival-in-progress",
        "archival-completed",
    ), status[0]
    assert "LastTieringStartTime" in status[0], status[0]

    # error boundary: real AWS validates the snapshot id format/existence for
    # ModifySnapshotTier via a generic InvalidParameterValue, not the
    # InvalidSnapshot.NotFound code used by most other snapshot operations.
    err, err_msg = _client_error(
        lambda: ec2.modify_snapshot_tier(SnapshotId="snap-00000000000000000", StorageTier="archive")
    )
    assert err == "InvalidParameterValue", err
    assert err_msg == "Value (snap-00000000000000000) for parameter snapshotId is invalid.", err_msg


def _best_effort_delete_snapshot(ctx, snapshot_id: str) -> None:
    ec2 = ctx.client("ec2")
    for _ in range(3):
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
