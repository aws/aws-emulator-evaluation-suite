"""op-contract-describeSnapshotAttribute."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSnapshotAttribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSnapshotAttribute reports the createVolumePermission list (empty for a
    freshly created, unshared snapshot) tagged to the right SnapshotId, and rejects a
    snapshot ID derived from a real one but not itself real."""
    ec2 = ctx.client("ec2")
    volume_id, snapshot_id = _create_volume_and_snapshot(ctx, ec2)

    resp = ec2.describe_snapshot_attribute(SnapshotId=snapshot_id, Attribute="createVolumePermission")
    assert resp["SnapshotId"] == snapshot_id, f"expected SnapshotId {snapshot_id!r}, got {resp['SnapshotId']!r}"
    assert resp["CreateVolumePermissions"] == [], f"expected no create-volume permissions, got {resp['CreateVolumePermissions']!r}"

    resp2 = ec2.describe_snapshot_attribute(SnapshotId=snapshot_id, Attribute="productCodes")
    assert resp2["SnapshotId"] == snapshot_id, f"expected SnapshotId {snapshot_id!r}, got {resp2['SnapshotId']!r}"
    assert resp2["ProductCodes"] == [], f"expected no product codes on a plain EBS snapshot, got {resp2['ProductCodes']!r}"

    # Flip the last hex digit of a real, just-issued snapshot ID to get one of the same
    # length that was never allocated. Depending on the real ID's digits, this single-digit
    # flip lands on EITHER side of AWS's own ID-validity check: sometimes the
    # mutated id still parses as a well-formed-but-never-issued id (InvalidSnapshot.NotFound),
    # sometimes the same kind of mutation fails AWS's own (undocumented) id-validity check
    # first (InvalidSnapshotID.Malformed). Both are a correct refusal to describe a snapshot
    # that isn't the real, accessible one -- accept either family, each with its exact message,
    # rather than pin a family that a re-run can flip.
    fake_snapshot_id = _fake_but_nonexistent_id(snapshot_id, "snap-")
    code, message = _error(
        lambda: ec2.describe_snapshot_attribute(
            SnapshotId=fake_snapshot_id, Attribute="createVolumePermission"
        )
    )
    expected = {
        "InvalidSnapshotID.Malformed": f"Value ( {fake_snapshot_id} ) for parameter SNAPSHOT is invalid. ",
        "InvalidSnapshot.NotFound": f"The snapshot '{fake_snapshot_id}' does not exist.",
    }
    assert code in expected, (
        f"expected InvalidSnapshot.NotFound or InvalidSnapshotID.Malformed, got {code!r} "
        f"(real_id={snapshot_id!r}, fake_id={fake_snapshot_id!r})"
    )
    assert message == expected[code], f"unexpected {code} message {message!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _fake_but_nonexistent_id(real_id, prefix):
    suffix = real_id[len(prefix):]
    last = suffix[-1]
    flipped = "0" if last != "0" else "1"
    return prefix + suffix[:-1] + flipped


def _create_volume_and_snapshot(ctx, ec2):
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-snapattr-")
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VolumeId"]

    def _cleanup_volume():
        try:
            ec2.delete_volume(VolumeId=volume_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                raise

    ctx.on_cleanup(_cleanup_volume)

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
    )

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=f"{name} snapshot",
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": name}]}],
    )["SnapshotId"]

    def _cleanup_snapshot():
        try:
            _poll_until(
                lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
                lambda s: s == "completed",
                timeout_s=180,
            )
        except AssertionError:
            pass
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise

    ctx.on_cleanup(_cleanup_snapshot)
    return volume_id, snapshot_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

