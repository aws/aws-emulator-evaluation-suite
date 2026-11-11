"""op-contract-create-volume."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-volume"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVolume: success creates an encrypted gp3 EBS volume that transitions to 'available'
    with the requested size/type/iops/encryption; a nonexistent snapshot id is rejected."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    name = ctx.unique_name("sim2real-behav-vol-")

    # --- error boundary: snapshot that doesn't exist ---
    # A hand-crafted "syntactically well-formed" random hex id is not a safe way to
    # probe this boundary: real AWS's format check on SnapshotId is stricter than a
    # simple "N lowercase-hex-chars" assumption, and a made-up id can come back
    # InvalidSnapshotID.Malformed instead of exercising the NotFound path. Create a
    # real snapshot, delete it, and reuse its (guaranteed well-formed, now
    # guaranteed absent) id instead.
    missing_snapshot_id = _make_missing_snapshot_id(ctx, az)
    code, message = _error(
        lambda: ec2.create_volume(
            AvailabilityZone=az, SnapshotId=missing_snapshot_id, VolumeType="gp3"
        )
    )
    assert code == "InvalidSnapshot.NotFound", f"unexpected code: {code}"
    assert message == "Snapshot does not exist", f"unexpected NotFound message: {message!r}"

    # --- success path ---
    resp = ec2.create_volume(
        AvailabilityZone=az,
        Size=10,
        VolumeType="gp3",
        Iops=3000,
        Encrypted=True,
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    volume_id = resp["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ctx, volume_id))
    assert resp["Size"] == 10, f"expected Size=10, got {resp['Size']!r}"
    assert resp["VolumeType"] == "gp3", f"expected VolumeType=gp3, got {resp['VolumeType']!r}"
    assert resp["AvailabilityZone"] == az, f"expected AvailabilityZone={az!r}, got {resp['AvailabilityZone']!r}"
    assert resp["State"] == "creating", f"expected State=creating, got {resp['State']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s in ("available", "error"),
        timeout_s=120.0,
    )
    assert final_state == "available", f"expected final State=available, volume ended in {final_state!r}"
    described = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert described["Iops"] == 3000, f"expected Iops=3000, got {described['Iops']!r}"
    assert described["Encrypted"] is True, f"expected Encrypted=True as requested, got {described['Encrypted']!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, Optional[str]]:
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _delete_volume(ctx, volume_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


def _delete_snapshot(ctx, snapshot_id: str) -> None:
    try:
        ctx.client("ec2").delete_snapshot(SnapshotId=snapshot_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
            raise


def _make_missing_snapshot_id(ctx, az: str) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    src_name = ctx.unique_name("sim2real-behav-srcvol-")
    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": src_name}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ctx, vol_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s in ("available", "error"),
        timeout_s=60.0,
    )
    snap_id = ec2.create_snapshot(
        VolumeId=vol_id,
        TagSpecifications=[{"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": src_name}]}],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: _delete_snapshot(ctx, snap_id))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda s: s in ("completed", "error"),
        timeout_s=180.0,
    )

    # --- positive control: CreateVolume from this still-existing snapshot must succeed ---
    # Without this, "rejects a nonexistent SnapshotId" below is indistinguishable from
    # "rejects every SnapshotId" — this proves the exact same id is accepted while the
    # snapshot exists, then the negative reuses it once deleted.
    control_name = ctx.unique_name("sim2real-behav-ctlvol-")
    control_resp = ec2.create_volume(
        AvailabilityZone=az,
        SnapshotId=snap_id,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": control_name}]}],
    )
    control_vol_id = control_resp["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ctx, control_vol_id))
    assert control_resp["State"] in ("creating", "available"), (
        f"expected control volume from a valid snapshot to start creating, got {control_resp['State']!r}"
    )
    control_final_state = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[control_vol_id])["Volumes"][0]["State"],
        lambda s: s in ("available", "error"),
        timeout_s=120.0,
    )
    assert control_final_state == "available", (
        f"expected control volume from a valid snapshot to become available, got {control_final_state!r}"
    )

    ec2.delete_snapshot(SnapshotId=snap_id)

    def _gone() -> bool:
        try:
            ec2.describe_snapshots(SnapshotIds=[snap_id])
            return False
        except ClientError as err:
            return err.response["Error"]["Code"] == "InvalidSnapshot.NotFound"

    _poll_until(lambda: _gone(), lambda gone: gone, timeout_s=60.0)
    return snap_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
