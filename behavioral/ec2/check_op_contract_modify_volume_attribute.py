"""op-contract-modify-volume-attribute."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-volume-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVolumeAttribute flips autoEnableIO and it is reflected by DescribeVolumeAttribute; a
    fabricated (but well-formed-looking) volume id is rejected as InvalidVolumeID.Malformed."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=8,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vol-")}],
            }
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60,
    )

    before = ec2.describe_volume_attribute(VolumeId=volume_id, Attribute="autoEnableIO")
    assert before["AutoEnableIO"]["Value"] is False, before

    ec2.modify_volume_attribute(VolumeId=volume_id, AutoEnableIO={"Value": True})

    after = ec2.describe_volume_attribute(VolumeId=volume_id, Attribute="autoEnableIO")
    assert after["AutoEnableIO"]["Value"] is True, after

    code, message = _client_error(
        lambda: ec2.modify_volume_attribute(VolumeId="vol-1234567890abcdef0", AutoEnableIO={"Value": True})
    )
    # This fabricated (but well-formed-looking) volume ID fails AWS's ID
    # validation before an existence check ever runs, so the API returns
    # .Malformed rather than .NotFound.
    assert code == "InvalidVolumeID.Malformed", f"unexpected error code: {code}"
    expected_message = "The volume ID 'vol-1234567890abcdef0' is malformed"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
