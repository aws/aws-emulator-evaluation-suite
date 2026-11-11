"""create-volume-nonexistent-snapshot-conflict-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-volume-nonexistent-snapshot-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVolume with a well-formed nonexistent SnapshotId fails with ValidationException and the exact
    InvalidSnapshotID.Malformed message; without a snapshot it creates a vol- volume that EC2 describes
    in the requested zone at 8 GiB.
    """
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    az = _available_zone(ctx)
    bogus_snapshot_id = "snap-00000000deadbeef"  # well-formed pattern, does not exist

    code, message = _error(
        lambda: _create_volume_once_slr_is_effective(
            wsi, AvailabilityZone=az, SnapshotId=bogus_snapshot_id
        )
    )
    assert code == "ValidationException", (
        f"CreateVolume with a well-formed but nonexistent SnapshotId {bogus_snapshot_id!r} "
        f"must be rejected with ValidationException; got {code!r}: {message}"
    )
    assert message == (
        f"Create volume failed (InvalidSnapshotID.Malformed: Value ( {bogus_snapshot_id} ) "
        "for parameter SNAPSHOT is invalid. )"
    ), message

    # positive control: an equivalent request without a bogus snapshot reference succeeds
    good = _create_volume_once_slr_is_effective(
        wsi,
        AvailabilityZone=az,
        SizeInGB=8,
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )
    good_volume_id = good["VolumeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_volume(wsi, good_volume_id))
    assert good_volume_id.startswith("vol-"), good_volume_id

    # independent read at the destination: the volume is a real, describable EBS volume on
    # the EC2 control plane, not merely an echo of the CreateVolume response
    described = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[good_volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert described["AvailabilityZone"] == az, described["AvailabilityZone"]
    assert described["Size"] == 8, described["Size"]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_volume_once_slr_is_effective(wsi, **kwargs):
    """A freshly created (or freshly-discovered-existing) service-linked role is not
    instantly effective for CreateVolume; retry ONLY the specific "Service-linked role is
    required" ValidationException on a bounded backoff, so it is never confused with the
    ValidationException this check's own negative case asserts."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120.0
    while True:
        try:
            return wsi.create_volume(**kwargs)
        except ClientError as e:
            error = e.response["Error"]
            if error["Code"] != "ValidationException" or "service-linked role" not in error.get(
                "Message", ""
            ).lower():
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "the workspaces-instances service-linked role never became effective "
                    "for CreateVolume within 120s"
                ) from e
            time.sleep(2)


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _best_effort_delete_volume(wsi, volume_id):
    try:
        wsi.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _available_zone(ctx) -> str:
    """The first zone the account reports available; zone letters map to different zones per account."""
    zones = ctx.client("ec2").describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]
    return sorted(z["ZoneName"] for z in zones)[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
