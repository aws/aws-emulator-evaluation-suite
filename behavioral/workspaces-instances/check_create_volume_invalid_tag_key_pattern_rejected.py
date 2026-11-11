"""create-volume-invalid-tag-key-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-volume-invalid-tag-key-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["workspaces-instances"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVolume with a tag Key outside the allowed characters fails with ValidationException and the
    exact pattern message; an allowed Key creates a vol- volume that EC2 describes with that tag.
    """
    wsi = ctx.client("workspaces-instances")
    ec2 = ctx.client("ec2")
    _ensure_service_linked_role(ctx)
    az = _available_zone(ctx)

    # Positive control first, and its acceptance is retried rather than gated behind a
    # blind sleep: a freshly created service-linked role can take a few seconds to
    # propagate before workspaces-instances can assume it.
    good_tag_specs = [
        {"ResourceType": "volume", "Tags": [{"Key": "good_key.value:1", "Value": "v"}]}
    ]

    def _create_good():
        return wsi.create_volume(AvailabilityZone=az, SizeInGB=8, TagSpecifications=good_tag_specs)

    good, good_err = _poll_until(
        lambda: _try(_create_good),
        lambda result: result[1] is None,
        timeout_s=60.0,
        interval_s=5.0,
        description="CreateVolume with an allowed-character tag key accepted",
    )
    assert good_err is None, good_err
    good_volume_id = good["VolumeId"]
    ctx.on_cleanup(lambda: _best_effort_delete_volume(wsi, good_volume_id))
    assert good_volume_id.startswith("vol-"), good_volume_id

    # Independent terminal read at the destination: the real EBS volume is visible
    # through EC2, carrying the tag the allowed key was accepted with.
    described = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[good_volume_id])["Volumes"][0],
        lambda v: bool(v.get("Tags")),
        timeout_s=60.0,
        interval_s=5.0,
        description=f"volume {good_volume_id} visible via EC2 with tags",
    )
    tag_values = {t["Key"]: t["Value"] for t in described["Tags"]}
    assert tag_values.get("good_key.value:1") == "v", described["Tags"]

    bad_tag_specs = [
        {"ResourceType": "volume", "Tags": [{"Key": "bad<>key!?", "Value": "v"}]}
    ]
    code, message = _error(
        lambda: wsi.create_volume(AvailabilityZone=az, SizeInGB=8, TagSpecifications=bad_tag_specs)
    )
    assert code == "ValidationException", (code, message)
    assert message == (
        "1 validation error detected: Value at 'tagSpecifications.1.member.tags.1.member.key' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "([\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+)"
    ), message


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="workspaces-instances.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0, description="condition"):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _try(fn):
    from botocore.exceptions import ClientError

    try:
        return fn(), None
    except ClientError as e:
        return None, e.response["Error"]["Code"]


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
