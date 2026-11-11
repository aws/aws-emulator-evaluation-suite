"""volume-modify-size-and-type-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "volume-modify-size-and-type-lifecycle"
GROUP = 'ebs-lifecycle'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
ERR_SHRINK_MESSAGE = "New size cannot be smaller than existing size"
# The ABSENCE of a modification is an ERROR, not an empty page.
# DescribeVolumesModifications(VolumeIds=[v]) for a volume that has never been modified raises
# InvalidVolumeModification.NotFound "Modification for volume 'vol-...' does not exist" -- it
# does not answer 200 with an empty VolumesModifications list. So "no modification yet" has to
# be asserted through that code, and the unfiltered call is the only one that pages normally.
ERR_NO_MODIFICATION = 'InvalidVolumeModification.NotFound'
_TERMINAL_MODIFICATION = ("optimizing", "completed")


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _an_az(ec2):
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    return zones[0]


def _wait_volume_state(ec2, volume_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _modification(ec2, volume_id):
    """The volume's modification record, or None if it has never been modified (which real EC2
    reports as ERR_NO_MODIFICATION rather than as an empty list)."""
    try:
        mods = ec2.describe_volumes_modifications(VolumeIds=[volume_id]).get(
            "VolumesModifications", []
        )
    except ClientError as exc:
        if _code(exc) == ERR_NO_MODIFICATION:
            return None
        raise
    return mods[0] if mods else None


def _assert_no_modification(ec2, volume_id, why):
    """Assert the volume has no modification record, the way real EC2 expresses it: the
    id-scoped lookup raises ERR_NO_MODIFICATION naming the volume, AND the unfiltered listing
    does not contain the volume. Both, because an implementation that raises for every volume
    would satisfy the first alone."""
    try:
        resp = ec2.describe_volumes_modifications(VolumeIds=[volume_id])
    except ClientError as exc:
        assert _code(exc) == ERR_NO_MODIFICATION, (
            f"{why}: expected {ERR_NO_MODIFICATION} looking up a nonexistent modification for "
            f"{volume_id}, got {_code(exc)}"
        )
        message = exc.response.get("Error", {}).get("Message", "")
        expected = f"Modification for volume '{volume_id}' does not exist."
        assert message == expected, (
            f"{why}: the {ERR_NO_MODIFICATION} message must be {expected!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"{why}: DescribeVolumesModifications answered 200 with "
            f"{resp.get('VolumesModifications')!r} for {volume_id}; real EC2 raises "
            f"{ERR_NO_MODIFICATION} when the volume has no modification"
        )
    listed = {
        m["VolumeId"]
        for page in ec2.get_paginator("describe_volumes_modifications").paginate()
        for m in page.get("VolumesModifications", [])
    }
    assert volume_id not in listed, (
        f"{why}: {volume_id} appears in the unfiltered DescribeVolumesModifications listing"
    )


def _wait_modification(ec2, volume_id, timeout_s=600):
    """Poll DescribeVolumesModifications to a TERMINAL modification state.

    ModifyVolume is EC2's own async state machine: modifying -> optimizing -> completed. It is
    reported by a separate resource (the volume modification), not by the volume's State, which
    stays 'available'/'in-use' throughout.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        mod = _modification(ec2, volume_id)
        last = mod["ModificationState"] if mod else "__none__"
        if last in _TERMINAL_MODIFICATION:
            return mod
        assert last != "failed", f"volume {volume_id} modification FAILED: {mod}"
        time.sleep(5)
    raise AssertionError(
        f"volume {volume_id} modification never reached {_TERMINAL_MODIFICATION} in {timeout_s}s (last {last!r})"
    )


def _delete_volume(ec2, volume_id):
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVolume grows and re-types a live volume through its own modifying->optimizing/
    completed modification record, and a shrink is rejected without touching the volume.
    """
    ec2 = ctx.client("ec2")
    az = _an_az(ec2)
    tag = [{"Key": "sim2real", "Value": "1"}]

    # --- volume A: the positive grow + re-type path ---
    vol_a = ec2.create_volume(
        AvailabilityZone=az, Size=1, VolumeType="gp2",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vol_a))
    _wait_volume_state(ec2, vol_a, "available")
    _assert_no_modification(ec2, vol_a, "a freshly created volume")

    mod = ec2.modify_volume(VolumeId=vol_a, Size=2, VolumeType="gp3")["VolumeModification"]
    assert mod["OriginalSize"] == 1 and mod["TargetSize"] == 2, (
        f"expected OriginalSize 1 -> TargetSize 2, got {mod['OriginalSize']} -> {mod['TargetSize']}"
    )
    assert mod["OriginalVolumeType"] == "gp2" and mod["TargetVolumeType"] == "gp3", (
        f"expected gp2 -> gp3, got {mod['OriginalVolumeType']} -> {mod['TargetVolumeType']}"
    )
    # The response state is transient; graded by membership, and the poll grades the terminal one.
    assert mod["ModificationState"] in ("modifying",) + _TERMINAL_MODIFICATION, (
        f"a fresh modification must be on its way to {_TERMINAL_MODIFICATION}, got "
        f"{mod['ModificationState']!r}"
    )

    settled = _wait_modification(ec2, vol_a)
    assert settled["TargetSize"] == 2, f"terminal modification lost TargetSize: {settled}"
    volume = ec2.describe_volumes(VolumeIds=[vol_a])["Volumes"][0]
    assert volume["Size"] == 2, f"expected the volume to report Size 2 after the modification, got {volume['Size']}"
    assert volume["VolumeType"] == "gp3", f"expected VolumeType gp3, got {volume['VolumeType']}"
    assert volume["State"] == "available", (
        f"a modified but unattached volume stays 'available', got {volume['State']!r}"
    )

    # --- volume B: break exactly one thing — ask for a SHRINK ---
    # A fresh volume is used because EC2 enforces a cooldown between successive modifications of
    # the SAME volume, which would mask the shrink rejection with a rate error.
    vol_b = ec2.create_volume(
        AvailabilityZone=az, Size=2, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume", "Tags": tag}],
    )["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ec2, vol_b))
    _wait_volume_state(ec2, vol_b, "available")

    try:
        ec2.modify_volume(VolumeId=vol_b, Size=1)
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} shrinking a volume 2GiB -> 1GiB, got {_code(exc)}"
        )
        message = exc.response.get("Error", {}).get("Message", "")
        assert message == ERR_SHRINK_MESSAGE, (
            f"expected the shrink refusal message {ERR_SHRINK_MESSAGE!r}, got {message!r}"
        )
    else:
        raise AssertionError(f"ModifyVolume shrinking {vol_b} from 2GiB to 1GiB must be rejected, it succeeded")

    # effect absent: no modification record, size untouched
    _assert_no_modification(ec2, vol_b, "after a rejected shrink")
    assert ec2.describe_volumes(VolumeIds=[vol_b])["Volumes"][0]["Size"] == 2, (
        "a rejected shrink must leave Size at 2"
    )

    # --- control: the same volume still accepts a legal GROW ---
    grow = ec2.modify_volume(VolumeId=vol_b, Size=3)["VolumeModification"]
    assert grow["TargetSize"] == 3, f"control grow to 3GiB not recorded, got {grow}"
    _wait_modification(ec2, vol_b)
    assert ec2.describe_volumes(VolumeIds=[vol_b])["Volumes"][0]["Size"] == 3, (
        "control grow must land: expected Size 3"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
