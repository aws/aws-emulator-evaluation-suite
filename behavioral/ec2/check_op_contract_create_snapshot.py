"""op-contract-create-snapshot."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-snapshot"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSnapshot: success snapshots an EBS volume through to completed; a fabricated
    VolumeId is rejected as malformed."""
    ec2 = ctx.client("ec2")
    az = _first_az(ctx)

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}]}
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
        interval_s=3.0,
    )

    resp = ec2.create_snapshot(
        VolumeId=vol_id,
        Description="sim2real behavioral check",
        TagSpecifications=[
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-snap-")}]}
        ],
    )
    snap_id = resp["SnapshotId"]
    ctx.on_cleanup(lambda: ec2.delete_snapshot(SnapshotId=snap_id))

    assert resp["VolumeId"] == vol_id, f"expected snapshot to reference volume {vol_id!r}, got {resp['VolumeId']!r}"
    assert resp["VolumeSize"] == 1, f"expected VolumeSize 1, got {resp['VolumeSize']!r}"
    assert resp["State"] in ("pending", "completed"), f"expected pending or completed, got {resp['State']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_snapshots(SnapshotIds=[snap_id])["Snapshots"][0]["State"],
        lambda s: s in ("completed", "error"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert final_state == "completed", f"snapshot ended in {final_state!r}"

    # Error boundary: a syntactically well-formed but never-issued VolumeId is rejected. Real AWS
    # validates the resource-ID checksum embedded in long-format IDs, so a hand-crafted ID (even
    # one with the correct "vol-" + 17 lowercase-hex-digit shape) fails that checksum and is
    # reported as malformed rather than as a genuine (checksum-valid but absent) not-found ID.
    code, message = _error_of(lambda: ec2.create_snapshot(VolumeId="vol-0123456789abcdef0"))
    assert code == "InvalidVolumeID.Malformed", f"expected InvalidVolumeID.Malformed, got {code!r}"
    assert message == "Value ( vol-0123456789abcdef0 ) for parameter VOLUME is invalid. ", message


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not observed within {timeout_s}s; last saw {last!r}")


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not zones:

        raise AssertionError("no available Availability Zone in this region")
    return zones[0]["ZoneName"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
