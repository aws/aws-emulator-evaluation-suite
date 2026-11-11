"""op-contract-deleteVolume."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVolume"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVolume removes an available EBS volume; re-deleting it is rejected InvalidVolume.NotFound."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[_tag_spec(ctx, "volume", "vol")],
    )["VolumeId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            try:
                ec2.delete_volume(VolumeId=volume_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    volume = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60.0,
    )
    assert volume["Size"] == 1, f"expected freshly created volume to report Size=1, got {volume['Size']!r}"
    assert volume["AvailabilityZone"] == az, (
        f"expected volume to report AvailabilityZone={az!r}, got {volume['AvailabilityZone']!r}"
    )

    ec2.delete_volume(VolumeId=volume_id)
    state["deleted"] = True

    def _probe_gone():
        try:
            described = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
            return described[0]["State"] if described else "gone"
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVolume.NotFound":
                return "gone"
            raise

    _poll_until(_probe_gone, lambda s: s == "gone", timeout_s=120.0)

    # distinct error boundary: re-deleting an already-deleted volume is rejected
    code, message = _error_of(lambda: ec2.delete_volume(VolumeId=volume_id))
    assert code == "InvalidVolume.NotFound", f"expected InvalidVolume.NotFound, got {code!r}"
    assert message == f"The volume '{volume_id}' does not exist.", message


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
