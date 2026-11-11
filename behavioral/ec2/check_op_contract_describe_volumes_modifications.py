"""op-contract-describe-volumes-modifications."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-describe-volumes-modifications"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVolumesModifications tracks a real resize and rejects DryRun."""
    ec2 = ctx.client("ec2")
    az = _first_available_az(ec2)

    vol = ec2.create_volume(AvailabilityZone=az, Size=8, VolumeType="gp3")
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, volume_id))

    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state == "available",
        timeout_s=90,
    )

    ec2.modify_volume(VolumeId=volume_id, Size=10)

    mod = _poll_until(
        lambda: _first_modification_or_none(ec2, volume_id),
        lambda m: m is not None,
        timeout_s=60,
    )
    assert mod["OriginalSize"] == 8, f"expected OriginalSize 8, got {mod['OriginalSize']}"
    assert mod["TargetSize"] == 10, f"expected TargetSize 10, got {mod['TargetSize']}"
    assert mod["ModificationState"] in ("modifying", "optimizing", "completed"), (
        f"expected an in-progress or completed modification state, got {mod['ModificationState']!r}"
    )

    code, message = _error(lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id], DryRun=True))
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"

    # The modification must settle before teardown can delete the volume.
    _poll_until(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"][0]["ModificationState"],
        lambda state: state in ("optimizing", "completed", "failed"),
        timeout_s=120,
    )


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _first_available_az(ec2) -> str:
    azs = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    assert azs, "no available AZs found"
    return azs[0]["ZoneName"]


def _first_modification_or_none(ec2, volume_id: str):
    """The volume's modification record, or None while it has not yet propagated.

    Right after ModifyVolume, AWS may raise InvalidVolumeModification.NotFound, not an empty list.
    """
    from botocore.exceptions import ClientError

    try:
        mods = ec2.describe_volumes_modifications(VolumeIds=[volume_id])["VolumesModifications"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "InvalidVolumeModification.NotFound":
            return None
        raise
    return mods[0] if mods else None


def _delete_volume(ec2, volume_id: str) -> None:
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"],
        lambda state: state in ("available", "error"),
        timeout_s=120,
    )
    ec2.delete_volume(VolumeId=volume_id)


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
