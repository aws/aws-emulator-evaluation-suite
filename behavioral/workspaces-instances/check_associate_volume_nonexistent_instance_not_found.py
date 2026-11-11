"""associate-volume-nonexistent-instance-not-found."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "associate-volume-nonexistent-instance-not-found"
GROUP = "error-semantics"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateVolume against a real volume but a never-created WorkspaceInstanceId returns
    ResourceNotFoundException, and the volume is left unattached (independently verified via
    ec2:DescribeVolumes)."""
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    az = _available_zone(ctx)
    just_created_slr = _ensure_service_linked_role(ctx)

    volume_id = _retry_after_slr_creation(
        lambda: wsi.create_volume(AvailabilityZone=az, SizeInGB=8, VolumeType="gp3")["VolumeId"],
        wait_needed=just_created_slr,
    )
    ctx.on_cleanup(lambda: _best_effort_delete_volume(wsi, volume_id))
    ec2.create_tags(Resources=[volume_id], Tags=[{"Key": "simparity-check", "Value": CHECK}])

    bogus_instance_id = "wsinst-00000000notreal"
    code, message = _error(
        lambda: wsi.associate_volume(
            WorkspaceInstanceId=bogus_instance_id, VolumeId=volume_id, Device="/dev/sdf"
        )
    )
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "Workspace instance is not found", message

    # effect absent: independent read at the destination shows the volume was never attached
    described = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert described.get("Attachments", []) == [], described.get("Attachments")


def _ensure_service_linked_role(ctx) -> bool:
    """Create the account's workspaces-instances SLR if absent. Returns True when this call
    just created it (fresh, might not be assumable yet) vs. False when it already existed
    (already propagated from an earlier run)."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise
        return False


def _retry_after_slr_creation(fn, wait_needed: bool, timeout_s: float = 30.0, interval_s: float = 3.0):
    """A freshly created service-linked role can take a few seconds to become assumable by
    the WorkSpaces Instances control plane. Retry the dependent call with backoff up to a
    stated deadline instead of a blind sleep -- and skip the wait entirely when the SLR already
    existed before this run."""
    import time

    from botocore.exceptions import ClientError

    if not wait_needed:
        return fn()
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            time.sleep(interval_s)
    raise last_exc


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _best_effort_delete_volume(wsi, volume_id, timeout_s=300.0):
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
