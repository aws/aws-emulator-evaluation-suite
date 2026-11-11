"""copy-snapshot-malformed-presigned-url-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-snapshot-malformed-presigned-url-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CopySnapshot rejects a structurally invalid PresignedUrl and creates no copy; the same
    source snapshot copies successfully once the unneeded PresignedUrl is omitted."""
    ec2 = ctx.client("ec2")

    az = _pick_availability_zone(ec2)
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-copysnap-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    ec2.get_waiter("volume_available").wait(VolumeIds=[volume_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    snap_id = ec2.create_snapshot(
        VolumeId=volume_id,
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-copysnap-src-")}]}
        ],
    )["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))
    ec2.get_waiter("snapshot_completed").wait(SnapshotIds=[snap_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    before_copies = _snapshot_ids_with_tag(ec2, "sim2real-copysnap-marker")

    code, message = _error_detail(
        lambda: ec2.copy_snapshot(
            SourceRegion=ctx.region,
            SourceSnapshotId=snap_id,
            PresignedUrl="not-a-valid-presigned-url",
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [{"Key": "sim2real-copysnap-marker", "Value": "bad-presigned"}],
                }
            ],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message})"
    assert message == "The protocol in PresignedUrl should be http or https", f"unexpected error message {message!r}"

    after_bad = _snapshot_ids_with_tag(ec2, "sim2real-copysnap-marker")
    assert after_bad == before_copies, (
        f"a snapshot copy was created despite the malformed PresignedUrl being rejected: {after_bad}"
    )

    result = ec2.copy_snapshot(
        SourceRegion=ctx.region,
        SourceSnapshotId=snap_id,
        TagSpecifications=[
            {
                "ResourceType": "snapshot",
                "Tags": [{"Key": "sim2real-copysnap-marker", "Value": "good-copy"}],
            }
        ],
    )
    copy_id = result["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=copy_id))

    completed = _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[copy_id])["Snapshots"][0],
        lambda s: s["State"] in ("completed", "error"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert completed["State"] == "completed", f"snapshot copy did not complete: {completed}"


def _pick_availability_zone(ec2) -> str:
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _snapshot_ids_with_tag(ec2, tag_key: str) -> set:
    resp = ec2.describe_snapshots(
        OwnerIds=["self"], Filters=[{"Name": f"tag-key", "Values": [tag_key]}]
    )
    return {s["SnapshotId"] for s in resp["Snapshots"]}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
