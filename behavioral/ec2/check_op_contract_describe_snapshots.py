"""op-contract-describeSnapshots."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSnapshots"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSnapshots reports the exact VolumeId/OwnerId/tags/description of a snapshot
    we just created once it reaches the terminal completed state, and rejects a never-issued
    snapshot ID derived from it as malformed or not found, with AWS's exact message."""
    ec2 = ctx.client("ec2")
    volume_id, snapshot_id, description, name = _create_volume_and_snapshot(ctx, ec2)

    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s in ("completed", "error"),
        timeout_s=300,
        interval_s=5,
    )
    resp = ec2.describe_snapshots(SnapshotIds=[snapshot_id], OwnerIds=["self"])
    snaps = resp["Snapshots"]
    assert len(snaps) == 1, f"expected exactly 1 snapshot, got {len(snaps)}"
    snap = snaps[0]
    assert snap["VolumeId"] == volume_id, f"expected VolumeId {volume_id!r}, got {snap['VolumeId']!r}"
    assert snap["Description"] == description, (
        f"expected Description {description!r}, got {snap['Description']!r}"
    )
    assert snap["State"] == "completed", f"unexpected state: {snap['State']!r}"
    tag_map = {t["Key"]: t["Value"] for t in snap.get("Tags", [])}
    assert tag_map.get("Name") == name, f"tags not reflected: {snap.get('Tags')!r}"

    # Build a never-issued snapshot ID by flipping the last hex digit of a real, just-issued ID,
    # matching this account/region's actual ID length. Measured on real AWS: whether the flipped
    # ID fails AWS's own ID-validity check (InvalidSnapshotID.Malformed) or passes it and misses
    # the lookup (InvalidSnapshot.NotFound) depends on the digits of the real ID, so a re-run can
    # land on either family. Each family carries its own exact message.
    fake_snapshot_id = _fake_but_nonexistent_id(snapshot_id, "snap-")
    code, message = _error(lambda: ec2.describe_snapshots(SnapshotIds=[fake_snapshot_id]))
    expected = {
        "InvalidSnapshotID.Malformed": f'Invalid id: "{fake_snapshot_id}"',
        "InvalidSnapshot.NotFound": f"The snapshot '{fake_snapshot_id}' does not exist.",
    }
    assert code in expected, (
        f"expected InvalidSnapshotID.Malformed or InvalidSnapshot.NotFound, got {code!r} "
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
    name = ctx.unique_name("sim2real-behav-snaps-")
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

    description = f"{name} snapshot"
    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        Description=description,
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
    return volume_id, snapshot_id, description, name


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
