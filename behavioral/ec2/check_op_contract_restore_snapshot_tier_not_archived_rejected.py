"""op-contract-restore-snapshot-tier-not-archived-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-restore-snapshot-tier-not-archived-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_NOT_ARCHIVED_CODES = (
    "InvalidSnapshot.NotArchived",
    "IncorrectState",
    "InvalidParameterValue",
    # Real AWS reports the state-conflict on a never-archived snapshot as a generic
    # invalid-state error rather than a snapshot-specific "not archived" code.
    "InvalidState",
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RestoreSnapshotTier on a standard-tier (never archived) snapshot fails with a not-archived error
    and its exact message, and the snapshot stays on the standard tier with no RestoreExpiryTime."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-rst-")
    volume_id = ec2.create_volume(
        Size=1,
        AvailabilityZone=az,
        VolumeType="gp3",
        TagSpecifications=[_tag_spec("volume", name)],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap_id = ec2.create_snapshot(
        VolumeId=volume_id, TagSpecifications=[_tag_spec("snapshot", name)]
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    desc = ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]
    assert desc.get("StorageTier", "standard") == "standard", (
        f"freshly created snapshot unexpectedly reports tier {desc.get('StorageTier')!r}"
    )

    code, message = _client_error(
        lambda: ec2.restore_snapshot_tier(SnapshotId=snap_id, PermanentRestore=True)
    )
    assert code in _NOT_ARCHIVED_CODES, f"unexpected error code: {code}"
    if code == "InvalidState":
        expected_message = "Cannot restore snapshot that has not been archived"
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the rejected call must not have perturbed the snapshot's own state --
    # proved via an independent read (describe_snapshots), not the mutating call's own
    # response.
    after_reject = ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]
    assert after_reject.get("StorageTier", "standard") == "standard", (
        f"rejected RestoreSnapshotTier call perturbed the storage tier: expected standard, "
        f"got {after_reject.get('StorageTier')!r}"
    )
    assert "RestoreExpiryTime" not in after_reject, (
        f"rejected RestoreSnapshotTier call unexpectedly set RestoreExpiryTime: {after_reject!r}"
    )


def _client_error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
