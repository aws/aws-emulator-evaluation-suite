"""op-contract-modify-volume."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-volume"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVolume resizes a gp3 volume and the modification progresses; a fabricated (but
    well-formed-looking) volume id fails AWS's ID validation before an existence check ever
    runs, so it -> InvalidVolumeID.Malformed, not NotFound."""
    ec2 = ctx.client("ec2")

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert azs, "no available AZs found"
    az = azs[0]["ZoneName"]
    volume_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=8,
        VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0],
        lambda v: v["State"] == "available",
        timeout_s=60,
    )

    resp = ec2.modify_volume(VolumeId=volume_id, Size=10)
    mod = resp["VolumeModification"]
    assert mod["TargetSize"] == 10, mod
    assert mod["ModificationState"] in ("modifying", "optimizing", "completed"), mod

    final = _poll_until(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"][0],
        lambda m: m["ModificationState"] in ("optimizing", "completed"),
        timeout_s=180,
    )
    assert final["TargetSize"] == 10, final

    # the modification record alone only echoes the request; the volume's own Size is the
    # independent proof that the resize actually landed.
    volume = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]
    assert volume["Size"] == 10, f"expected the volume to report Size 10 after modification, got {volume['Size']}"

    code, message = _client_error(lambda: ec2.modify_volume(VolumeId="vol-1234567890abcdef0", Size=10))
    assert code == "InvalidVolumeID.Malformed", f"unexpected error code: {code}"
    expected_message = "Value ( vol-1234567890abcdef0 ) for parameter VOLUME is invalid. "
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
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
