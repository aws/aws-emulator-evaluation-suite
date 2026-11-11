"""create-volume-iops-exceeds-range-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-volume-iops-exceeds-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVolume with a gp3 Iops far above the EBS maximum is rejected with ValidationException
    and creates no volume (checked via EC2), while an in-range Iops succeeds and EC2 reports it,
    so the rejection is attributable to the Iops value."""
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    az = _available_zone(ctx)

    # positive control: an in-range gp3 Iops value succeeds. Retried on a bounded window
    # because a freshly-created service-linked role can take a few seconds to propagate to
    # the workspaces-instances control plane -- a real wait condition, not a blind sleep.
    good_token = ctx.unique_name("iops-range-good-")
    good_volume_id = _retry_while_role_propagates(
        lambda: wsi.create_volume(
            AvailabilityZone=az,
            SizeInGB=10,
            VolumeType="gp3",
            Iops=3000,
            ClientToken=good_token,
        )["VolumeId"]
    )
    ctx.on_cleanup(lambda: _delete_volume(wsi, good_volume_id))
    described = ec2.describe_volumes(VolumeIds=[good_volume_id])["Volumes"][0]
    assert described["VolumeType"] == "gp3", (
        f"expected the positive control to describe as a gp3 volume, got "
        f"{described['VolumeType']!r}"
    )
    assert described["Iops"] == 3000, (
        f"expected the positive control to carry Iops=3000 in EC2's own view, got "
        f"{described.get('Iops')!r}"
    )

    # negative: an Iops value far outside the gp3 window (3,000-16,000) is rejected, and no
    # volume is created as a side effect. The tag is unique to this run so the absence check
    # is robust to concurrent activity elsewhere in a shared sandbox account, and the cleanup
    # is registered up front so an unexpectedly-accepted call still cannot leak.
    marker_tag = ctx.unique_name("iops-range-marker-")
    ctx.on_cleanup(lambda: _delete_volumes_by_tag(ec2, wsi, marker_tag))
    code, message = _error(
        lambda: wsi.create_volume(
            AvailabilityZone=az,
            SizeInGB=10,
            VolumeType="gp3",
            Iops=999999,
            TagSpecifications=[
                {"ResourceType": "volume", "Tags": [{"Key": marker_tag, "Value": "probe"}]}
            ],
        )
    )
    assert code == "ValidationException", (
        f"expected an out-of-range Iops to be rejected with ValidationException, got {code!r}: {message}"
    )
    assert message == (
        "Create volume failed (InvalidParameterValue: Volume iops of 999999 is too high; "
        "maximum is 80000.)"
    ), message
    leaked = ec2.describe_volumes(Filters=[{"Name": f"tag:{marker_tag}", "Values": ["probe"]}])[
        "Volumes"
    ]
    assert leaked == [], f"the rejected CreateVolume call left a volume behind: {leaked!r}"


# ===== helpers =====
def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _retry_while_role_propagates(fn, timeout_s=30.0, interval_s=3.0):
    """A freshly-created service-linked role can take a few seconds to become usable by the
    workspaces-instances control plane; retry the bounded window instead of sleeping blind."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(
        f"create_volume did not succeed within {timeout_s}s of service-linked role setup: "
        f"{last_err}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    a target that accepts a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


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


def _delete_volumes_by_tag(ec2, wsi, marker_tag):
    vols = ec2.describe_volumes(Filters=[{"Name": f"tag:{marker_tag}", "Values": ["probe"]}])[
        "Volumes"
    ]
    for v in vols:
        _delete_volume(wsi, v["VolumeId"])


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
