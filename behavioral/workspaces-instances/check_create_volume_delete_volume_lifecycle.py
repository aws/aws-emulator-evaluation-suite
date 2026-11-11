"""create-volume-delete-volume-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-volume-delete-volume-lifecycle"
GROUP = "data-plane"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVolume makes a 20 GiB gp3 volume that EC2 describes in the requested zone; once DeleteVolume
    removes it, a second DeleteVolume fails with ResourceNotFoundException and the exact message.
    """
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    az = _available_zone(ctx)

    created = _call_with_role_propagation_retry(
        lambda: wsi.create_volume(AvailabilityZone=az, SizeInGB=20, VolumeType="gp3")
    )
    volume_id = created["VolumeId"]
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            try:
                wsi.delete_volume(VolumeId=volume_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup)

    # the volume is a real EBS volume, independently visible through the EC2 control plane
    described = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert described["AvailabilityZone"] == az, f"expected AZ {az!r}, got {described['AvailabilityZone']!r}"
    assert described["Size"] == 20, f"expected Size 20, got {described['Size']!r}"
    assert described["VolumeType"] == "gp3", f"expected VolumeType 'gp3', got {described['VolumeType']!r}"

    wsi.delete_volume(VolumeId=volume_id)
    deleted["done"] = True

    # deletion is asynchronous on the EC2 side; the volume transitions through a "deleting"
    # state during which a repeat DeleteVolume observes ConflictException rather than
    # ResourceNotFoundException -- poll until the volume is actually gone before asserting
    # the terminal not-found semantics.
    def _fully_gone():
        from botocore.exceptions import ClientError

        try:
            ec2.describe_volumes(VolumeIds=[volume_id])
            return False
        except ClientError as e:
            return e.response["Error"]["Code"] == "InvalidVolume.NotFound"

    _poll_until(_fully_gone, lambda gone: gone, timeout_s=120.0, interval_s=5.0)

    code, message = _error(lambda: wsi.delete_volume(VolumeId=volume_id))
    assert code == "ResourceNotFoundException", (code, message)
    assert message == "Workspace managed EBS volume is not found", message


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _call_with_role_propagation_retry(fn, timeout_s=90.0, interval_s=5.0):
    """A freshly-created service-linked role can take a few seconds to propagate before
    workspaces-instances can assume it; retry on the specific propagation-shaped errors
    rather than sleeping blind."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "retry loop exited with no error captured"
    raise last_err


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


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
