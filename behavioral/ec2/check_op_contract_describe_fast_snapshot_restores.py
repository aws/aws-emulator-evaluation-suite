"""op-contract-describeFastSnapshotRestores."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeFastSnapshotRestores"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """DescribeFastSnapshotRestores, scoped by filter to our own snapshot, reflects the
    real enable -> disable lifecycle (absent, then present with the enabling AZ/state,
    then transitioned by disable) and rejects an unknown filter name server-side."""
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
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snapshot_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-snap-")}]}
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snapshot_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    def _describe_own():
        resp = ec2.describe_fast_snapshot_restores(
            Filters=[
                {"Name": "snapshot-id", "Values": [snapshot_id]},
                {"Name": "availability-zone", "Values": [az]},
            ]
        )
        items = resp["FastSnapshotRestores"]
        assert len(items) <= 1, f"expected at most one entry for {snapshot_id}/{az}, got {items!r}"
        return items[0] if items else None

    # --- before enabling: the filtered, scoped-to-our-snapshot query is empty ---
    assert _describe_own() is None, f"expected no FSR entry for {snapshot_id} before enabling"

    ec2.enable_fast_snapshot_restores(AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id])
    ctx.on_cleanup(
        lambda: ec2.disable_fast_snapshot_restores(AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id])
    )

    enabled_entry = _wait_until_not_none(_describe_own, timeout_s=60, interval_s=3)
    assert enabled_entry["SnapshotId"] == snapshot_id, enabled_entry["SnapshotId"]
    assert enabled_entry["AvailabilityZone"] == az, enabled_entry["AvailabilityZone"]
    assert enabled_entry["State"] in ("enabling", "optimizing", "enabled"), enabled_entry["State"]

    ec2.disable_fast_snapshot_restores(AvailabilityZones=[az], SourceSnapshotIds=[snapshot_id])

    def _disabling_or_gone():
        entry = _describe_own()
        if entry is None:
            return True
        return entry["State"] in ("disabling", "disabled") or None

    _wait_until_true(_disabling_or_gone, timeout_s=60, interval_s=3)

    # --- error boundary: an unknown filter name must be rejected server-side ---
    def _call():
        ec2.describe_fast_snapshot_restores(
            Filters=[{"Name": "sim2real-not-a-real-filter", "Values": ["x"]}]
        )

    code, message = _error(_call)
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == "The filter 'sim2real-not-a-real-filter' is invalid", (
        f"expected the exact InvalidParameterValue message, got {message!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _wait_until_not_none(probe: Callable[[], Any], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last is not None:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"never observed a non-None value within {timeout_s}s, last observed {last!r}")


def _wait_until_true(probe: Callable[[], Any], *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last:
            return
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s, last observed {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
