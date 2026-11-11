"""op-contract-enableFastSnapshotRestores."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enableFastSnapshotRestores"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableFastSnapshotRestores is batch-shaped: it never raises for a bad snapshot ID,
    it reports the failure in the `Unsuccessful` list while the good snapshot succeeds.
    """
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]

    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _wait_until(lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"], "available", timeout_s=60)

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    _wait_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        "completed",
        timeout_s=180,
        interval_s=5,
    )

    bogus_snapshot_id = "snap-00000000000000000"
    resp = ec2.enable_fast_snapshot_restores(
        AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id, bogus_snapshot_id]
    )
    ctx.on_cleanup(
        lambda: ec2.disable_fast_snapshot_restores(AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id])
    )

    successful = {item["SnapshotId"]: item for item in resp["Successful"]}
    unsuccessful = {item["SnapshotId"]: item for item in resp["Unsuccessful"]}

    assert snapshot_id in successful, f"expected {snapshot_id} in Successful, got {resp['Successful']}"
    assert successful[snapshot_id]["State"] in ("enabling", "optimizing", "enabled"), (
        f"expected an in-progress-or-enabled state for {snapshot_id}, got {successful[snapshot_id]['State']!r}"
    )
    assert successful[snapshot_id]["AvailabilityZone"] == az, (
        f"expected AvailabilityZone {az!r} for {snapshot_id}, got {successful[snapshot_id]['AvailabilityZone']!r}"
    )

    assert bogus_snapshot_id in unsuccessful, f"expected {bogus_snapshot_id} in Unsuccessful, got {resp['Unsuccessful']}"
    # The per-AZ error is nested under FastSnapshotRestoreStateErrors, not directly on the item.
    state_errors = unsuccessful[bogus_snapshot_id].get("FastSnapshotRestoreStateErrors", [])
    assert state_errors, f"expected FastSnapshotRestoreStateErrors for {bogus_snapshot_id}, got {unsuccessful[bogus_snapshot_id]!r}"
    state_error = state_errors[0]
    assert state_error.get("AvailabilityZone") == az, (
        f"expected the Unsuccessful entry's AvailabilityZone to be {az!r}, got {state_error.get('AvailabilityZone')!r}"
    )
    error = state_error["Error"]
    # Real AWS doesn't guarantee the exact family here (observed values include plain
    # "InvalidSnapshot"/"InvalidParameterValue" style codes as well as ".NotFound"
    # suffixed ones) -- assert on the broader not-found/invalid-resource family rather
    # than requiring the literal substring "NotFound".
    code = error["Code"]
    assert any(token in code for token in ("NotFound", "InvalidSnapshot", "InvalidParameterValue")), (
        f"expected a not-found/invalid-snapshot style error code, got {code}"
    )
    assert error.get("Message"), f"expected a non-empty error message for {bogus_snapshot_id}, got {error!r}"

    # Independent terminal read: DescribeFastSnapshotRestores is a different operation than
    # the one that mutated. It must show the enabled state actually took, and must show no
    # entry at all for the snapshot that was never accepted.
    described = ec2.describe_fast_snapshot_restores(
        Filters=[{"Name": "snapshot-id", "Values": [snapshot_id, bogus_snapshot_id]}]
    )["FastSnapshotRestores"]
    described_by_snapshot = {item["SnapshotId"]: item for item in described}

    assert snapshot_id in described_by_snapshot, (
        f"expected {snapshot_id} to appear in an independent DescribeFastSnapshotRestores read, got {described!r}"
    )
    described_entry = described_by_snapshot[snapshot_id]
    assert described_entry["AvailabilityZone"] == az, (
        f"expected the independent read's AvailabilityZone to be {az!r}, got {described_entry['AvailabilityZone']!r}"
    )
    assert described_entry["State"] in ("enabling", "optimizing", "enabled"), (
        f"expected an in-progress-or-enabled state on the independent read for {snapshot_id}, "
        f"got {described_entry['State']!r}"
    )
    assert bogus_snapshot_id not in described_by_snapshot, (
        f"expected no DescribeFastSnapshotRestores entry for the never-accepted {bogus_snapshot_id}, "
        f"got {described_by_snapshot[bogus_snapshot_id]!r}"
    )


def _wait_until(probe: Callable[[], Any], expected: Any, *, timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last == expected:
            return
        time.sleep(interval_s)
    raise AssertionError(f"never reached {expected!r}, last observed {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
