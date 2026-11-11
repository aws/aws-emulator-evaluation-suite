"""op-contract-disable-fast-snapshot-restores."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-disable-fast-snapshot-restores"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisableFastSnapshotRestores reports an owned snapshot's enabled zone as successfully disabling,
    as DescribeFastSnapshotRestores confirms after enable and after disable; a request naming neither
    zone form fails with MissingParameter and its exact message."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    snapshot_id = _create_test_snapshot(ctx, az)

    enable_resp = ec2.enable_fast_snapshot_restores(
        AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id]
    )
    assert enable_resp["Unsuccessful"] == [], f"enable unsuccessful: {enable_resp['Unsuccessful']}"
    assert len(enable_resp["Successful"]) == 1, f"expected 1 successful item, got {enable_resp['Successful']}"
    assert enable_resp["Successful"][0]["SnapshotId"] == snapshot_id, (
        f"expected {snapshot_id}, got {enable_resp['Successful'][0]['SnapshotId']}"
    )

    enabled = _describe_restore(ec2, snapshot_id, az)
    assert enabled is not None, f"expected {snapshot_id}/{az} in DescribeFastSnapshotRestores after enable, found none"
    assert enabled["State"] in ("enabling", "optimizing", "enabled"), (
        f"unexpected state from independent read after enable: {enabled['State']}"
    )

    def _cleanup():
        ec2.disable_fast_snapshot_restores(AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id])

    ctx.on_cleanup(_cleanup)

    disable_resp = ec2.disable_fast_snapshot_restores(
        AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id]
    )
    assert disable_resp["Unsuccessful"] == [], f"disable unsuccessful: {disable_resp['Unsuccessful']}"
    assert len(disable_resp["Successful"]) == 1, f"expected 1 successful item, got {disable_resp['Successful']}"
    item = disable_resp["Successful"][0]
    assert item["SnapshotId"] == snapshot_id, f"expected {snapshot_id}, got {item['SnapshotId']}"
    assert item["State"] in ("disabling", "disabled"), f"unexpected state: {item['State']}"

    # Independent read at the destination: DescribeFastSnapshotRestores, not the mutating
    # call's own response, is what settles whether the disable actually took effect.
    disabled = _describe_restore(ec2, snapshot_id, az)
    assert disabled is None or disabled["State"] in ("disabling", "disabled"), (
        f"expected the entry gone or disabling/disabled from an independent read, got {disabled}"
    )

    # Neither AvailabilityZone nor AvailabilityZoneId supplied -> AWS-side validation error.
    code, message = _error(lambda: ec2.disable_fast_snapshot_restores(SourceSnapshotIds=[snapshot_id]))
    assert code == "MissingParameter", (
        f"expected a missing-AZ validation error, got {code}"
    )
    assert message == "AvailabilityZone or AvailabilityZoneId must be specified in the request, but not both.", (
        f"unexpected missing-AZ validation message: {message!r}"
    )


def _describe_restore(ec2, snapshot_id: str, az: str) -> dict | None:
    resp = ec2.describe_fast_snapshot_restores(
        Filters=[{"Name": "snapshot-id", "Values": [snapshot_id]}]
    )
    for item in resp["FastSnapshotRestores"]:
        if item["AvailabilityZone"] == az:
            return item
    return None


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must not read as a
    code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_test_snapshot(ctx, az: str) -> str:
    ec2 = ctx.client("ec2")
    vol = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{
            "ResourceType": "volume",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}],
        }],
    )
    vol_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[vol_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{
            "ResourceType": "snapshot",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}],
        }],
    )
    snap_id = snap["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return snap_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
