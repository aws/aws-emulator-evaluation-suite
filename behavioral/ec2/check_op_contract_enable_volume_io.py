"""op-contract-enable-volume-io."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-enable-volume-io"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """EnableVolumeIO on an available volume with I/O already enabled fails with IncorrectState; a
    malformed volume ID fails with InvalidParameterValue and a well-formed unknown one with
    InternalError, each with its exact message."""
    ec2 = ctx.client("ec2")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    vol_id = ec2.create_volume(
        AvailabilityZone=az,
        Size=1,
        VolumeType="gp3",
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "sim2real", "Value": "true"}],
            }
        ],
    )["VolumeId"]
    ctx.on_cleanup(lambda: ec2.delete_volume(VolumeId=vol_id))
    _wait_for(lambda: ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]["State"] == "available")

    # --- success-path contract: a healthy, already I/O-enabled volume has nothing to
    # re-enable, so EnableVolumeIO rejects the redundant call with IncorrectState ---
    code, message = _error(lambda: ec2.enable_volume_io(VolumeId=vol_id))
    assert code == "IncorrectState", f"expected IncorrectState, got {code!r}"
    assert message == f"Volume {vol_id} already has IO enabled.", f"unexpected IncorrectState message: {message!r}"

    # confirm the volume is still healthy and usable afterwards
    vol = ec2.describe_volumes(VolumeIds=[vol_id])["Volumes"][0]
    assert vol["State"] == "available", f"expected available, got {vol['State']!r}"

    # --- error boundary: malformed (non-EC2-shaped) volume id ---
    malformed_code, malformed_message = _error(lambda: ec2.enable_volume_io(VolumeId="not-a-real-volume-id"))
    assert malformed_code == "InvalidParameterValue", f"expected InvalidParameterValue, got {malformed_code!r}"
    assert malformed_message == "Value (not-a-real-volume-id) for parameter volumeId is invalid. Expected: 'vol-...'.", (
        f"unexpected InvalidParameterValue message: {malformed_message!r}"
    )

    # --- error boundary: a well-formed nonexistent volume ID draws InternalError here, not the
    # InvalidVolume.NotFound of most EC2 operations, and a different code from the malformed ID, so the
    # rejection tracks the input fault ---
    notfound_code, notfound_message = _error(lambda: ec2.enable_volume_io(VolumeId="vol-00000000000000000"))
    assert notfound_code == "InternalError", f"expected InternalError, got {notfound_code!r}"
    assert notfound_message == "An internal error has occurred", f"unexpected InternalError message: {notfound_message!r}"
    assert notfound_code != malformed_code, (
        f"not-found and malformed-id codes must differ to prove input classification: "
        f"got {notfound_code!r} for both"
    )


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
