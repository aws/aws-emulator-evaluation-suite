"""copy-snapshot-cross-account-without-permission-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "copy-snapshot-cross-account-without-permission-blocked"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopySnapshot rejects a snapshot id the caller has no create-volume-permission on and creates
    no snapshot; copying a snapshot the caller owns succeeds. AWS answers "does not exist" and
    "not shared with you" alike so existence does not leak across accounts."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-copysnap-")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    volume_id = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp3", TagSpecifications=_tag_spec("volume", name)
    )["VolumeId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_volume(VolumeId=volume_id)))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=3,
    )

    snapshot_id = ec2.create_snapshot(VolumeId=volume_id, TagSpecifications=_tag_spec("snapshot", name))[
        "SnapshotId"
    ]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_snapshot(SnapshotId=snapshot_id)))
    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snapshot_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=300,
        interval_s=5,
    )

    own_snapshot_ids_before = _own_snapshot_ids(ec2)

    # ---- Negative: a syntactically valid snapshot ID this account has never
    # created and has no create-volume-permission on is rejected, not copied ----
    inaccessible_snapshot_id = "snap-0123456789abcdef0"
    assert inaccessible_snapshot_id not in own_snapshot_ids_before, (
        f"fabricated id {inaccessible_snapshot_id!r} is unexpectedly already one of this "
        f"account's own snapshots: {own_snapshot_ids_before!r}"
    )

    code, message = _error_detail(
        lambda: ec2.copy_snapshot(
            SourceRegion=ctx.region,
            SourceSnapshotId=inaccessible_snapshot_id,
            Description="sim2real cross-account copy negative",
        )
    )
    # CopySnapshot answers InvalidParameterValue here, not the InvalidSnapshot.NotFound that
    # DescribeSnapshots/DeleteSnapshot use.
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message})"
    assert message == "The specified snapshotId is invalid", f"unexpected error message {message!r}"

    # Effect absence: no new snapshot was created as a side effect of the rejected copy.
    own_snapshot_ids_after = _own_snapshot_ids(ec2)
    assert own_snapshot_ids_after == own_snapshot_ids_before, (
        f"rejected copy_snapshot still produced a snapshot: "
        f"{own_snapshot_ids_after - own_snapshot_ids_before!r}"
    )

    # ---- Positive control: copying a snapshot the caller actually owns succeeds ----
    copy_resp = ec2.copy_snapshot(
        SourceRegion=ctx.region,
        SourceSnapshotId=snapshot_id,
        Description="sim2real same-account copy positive control",
        TagSpecifications=_tag_spec("snapshot", name + "-copy"),
    )
    copy_id = copy_resp["SnapshotId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_snapshot(SnapshotId=copy_id)))

    _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[copy_id])["Snapshots"][0]["State"],
        lambda s: s == "completed",
        timeout_s=300,
        interval_s=5,
    )


def _own_snapshot_ids(ec2) -> set[str]:
    snaps = ec2.describe_snapshots(OwnerIds=["self"])["Snapshots"]
    return {s["SnapshotId"] for s in snaps}


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _error_detail(fn: Callable[[], Any]):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidSnapshot.NotFound",
            "InvalidVolume.NotFound",
        ):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
