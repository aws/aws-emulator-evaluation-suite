"""create-volume-clienttoken-reuse-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-volume-clienttoken-reuse-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVolume reusing a committed ClientToken, even with identical parameters, fails with
    ConflictException and the exact message; a fresh token creates a second 8 GiB gp3 volume in the
    same zone, and both are described.
    """
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    az = _available_zone(ctx)
    token = ctx.unique_name("sim2real-vtok-")[:64]
    created_ids = []
    ctx.on_cleanup(lambda: _best_effort_delete_volumes(wsi, created_ids))

    first = wsi.create_volume(
        AvailabilityZone=az,
        SizeInGB=8,
        VolumeType="gp3",
        ClientToken=token,
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real-check", "Value": token}]}],
    )
    first_id = first["VolumeId"]
    created_ids.append(first_id)

    code, message = _error(
        lambda: wsi.create_volume(
            AvailabilityZone=az,
            SizeInGB=8,
            VolumeType="gp3",
            ClientToken=token,
            TagSpecifications=[
                {"ResourceType": "volume", "Tags": [{"Key": "sim2real-check", "Value": token}]}
            ],
        )
    )
    assert code == "ConflictException", (code, message)
    assert message == "The client token provided does not match the request", message

    # restore: an identical CreateVolume call with a FRESH token succeeds, proving the
    # rejection is specific to token reuse and not a general block on this AZ/params.
    fresh_token = ctx.unique_name("sim2real-vtok-")[:64]
    second = wsi.create_volume(
        AvailabilityZone=az,
        SizeInGB=8,
        VolumeType="gp3",
        ClientToken=fresh_token,
        TagSpecifications=[
            {"ResourceType": "volume", "Tags": [{"Key": "sim2real-check", "Value": fresh_token}]}
        ],
    )
    second_id = second["VolumeId"]
    assert second_id != first_id, second_id
    created_ids.append(second_id)

    # independent read at the destination: EC2's own DescribeVolumes, not either
    # CreateVolume call's own response, confirms both are real and distinct.
    described = ec2.describe_volumes(VolumeIds=[first_id, second_id])["Volumes"]
    described_ids = sorted(v["VolumeId"] for v in described)
    assert described_ids == sorted([first_id, second_id]), described_ids
    for volume in described:
        assert volume["AvailabilityZone"] == az, volume
        assert volume["Size"] == 8, volume
        assert volume["VolumeType"] == "gp3", volume


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _ensure_service_linked_role(ctx):
    import time

    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise

    deadline = time.monotonic() + 30.0
    while True:
        roles = iam.list_roles(
            PathPrefix="/aws-service-role/workspaces-instances.amazonaws.com/"
        )["Roles"]
        if roles:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                "service-linked role for workspaces-instances.amazonaws.com not visible "
                "within 30s of CreateServiceLinkedRole"
            )
        time.sleep(2.0)


def _best_effort_delete_volumes(wsi, volume_ids):
    for volume_id in volume_ids:
        _delete_volume(wsi, volume_id)


def _delete_volume(wsi, volume_id, timeout_s=300.0):
    """Delete the volume: gone is done; ConflictException (the volume is not yet available) and
    throttling are retried every 2 s to the deadline, inside the 1200 s cleanup budget; anything else raises."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            wsi.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ConflictException", "ThrottlingException") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _available_zone(ctx) -> str:
    """The first zone the account reports available; zone letters map to different zones per account."""
    zones = ctx.client("ec2").describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]},
                 {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]
    return sorted(z["ZoneName"] for z in zones)[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
