"""multiattach-modify-of-an-io2-volume-to-gp3-is-refused-until-the-flag-is-cleared."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiattach-modify-of-an-io2-volume-to-gp3-is-refused-until-the-flag-is-cleared"
GROUP = 'multiattach-volume-type'
SERVICES = ['ec2']

SIZE_GIB = 4
IO2_IOPS = 100
ERR_BAD_COMBINATION = 'InvalidParameterCombination'
ERR_NO_MODIFICATION = 'InvalidVolumeModification.NotFound'

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


class _UnexpectedSuccess(Exception):
    """Raised when a call the check expects to be refused succeeds."""


def _error_of(fn):
    """(code, message) for a call that MUST fail. Raises _UnexpectedSuccess if it does not."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise _UnexpectedSuccess(f"the call succeeded and returned {resp!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last observation: {last!r}"
    )


def _usable_az(ctx):
    """One AZ that is 'available' and offers m5.large (Nitro), as Multi-Attach requires.

    AZ names are per-account aliases, so the zone is derived rather than named.
    """
    ec2 = ctx.client("ec2")
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    offering = set()
    for page in ec2.get_paginator("describe_instance_type_offerings").paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["m5.large"]}]):
        offering.update(off["Location"] for off in page["InstanceTypeOfferings"])
    usable = sorted(available & offering)
    assert usable, (
        f"no available AZ in {ctx.region} offers the Nitro instance family Multi-Attach requires; "
        f"available zones were {sorted(available)!r} and offerings were {sorted(offering)!r}"
    )
    return usable[0]


def _describe_volume(ctx, volume_id):
    """DescribeVolumes for one id, paginated."""
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _modifications(ctx, volume_id):
    """Every modification record for one volume, paginated.

    DescribeVolumesModifications raises InvalidVolumeModification.NotFound for an unmodified volume.
    """
    ec2 = ctx.client("ec2")
    found = []
    for page in ec2.get_paginator("describe_volumes_modifications").paginate(
            VolumeIds=[volume_id]):
        found.extend(page.get("VolumesModifications", []))
    return found


def _delete_volume(ctx, volume_id, timeout_s=300):
    """Delete, retrying only the refusals of a volume still settling (IncorrectState, VolumeInUse)."""
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            if _code(exc) not in ("IncorrectState", "VolumeInUse") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ModifyVolume io2 -> gp3 on a Multi-Attach volume is refused InvalidParameterCombination and
    queues no modification; the same call with MultiAttachEnabled=False succeeds on the same volume.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volumes-multi.html
    """
    ec2 = ctx.client("ec2")
    az = _usable_az(ctx)
    tag_spec = [{"ResourceType": "volume", "Tags": [
        {"Key": "sim2real", "Value": "multiattach-modify"},
        {"Key": "Name", "Value": ctx.unique_name("sim2real-multiattach-modify-")},
    ]}]

    created = ec2.create_volume(AvailabilityZone=az, Size=SIZE_GIB, VolumeType="io2",
                               Iops=IO2_IOPS, MultiAttachEnabled=True,
                               TagSpecifications=tag_spec)
    volume_id = created["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ctx, volume_id))
    assert created.get("MultiAttachEnabled") is True, (
        f"the io2 volume {volume_id} reported MultiAttachEnabled "
        f"{created.get('MultiAttachEnabled')!r} at creation, expected True — the state the refusal "
        f"is supposed to depend on was never established"
    )
    _poll_until(lambda: _describe_volume(ctx, volume_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=3,
                description=f"io2 Multi-Attach volume {volume_id} reaches 'available'")

    code, message = _error_of(
        lambda: ec2.modify_volume(VolumeId=volume_id, VolumeType="gp3"))
    assert code == ERR_BAD_COMBINATION, (
        f"ModifyVolume(VolumeType='gp3') on the Multi-Attach volume {volume_id} must be refused "
        f"with exactly {ERR_BAD_COMBINATION!r}, got {code!r}: {message!r}"
    )
    assert message == "The parameter multi-attach-enabled is not supported for gp3 volumes.", (
        f"ModifyVolume(VolumeType='gp3') refusal message on {volume_id}: {message!r}"
    )

    refused = _describe_volume(ctx, volume_id)
    assert (refused["VolumeType"], refused["MultiAttachEnabled"], refused["Iops"]) == (
        "io2", True, IO2_IOPS), (
        f"after the refusal {volume_id} reads VolumeType {refused['VolumeType']!r}, "
        f"MultiAttachEnabled {refused['MultiAttachEnabled']!r}, Iops {refused['Iops']!r}; expected "
        f"('io2', True, {IO2_IOPS}) — the refused modify took effect anyway"
    )
    assert refused["State"] == "available", (
        f"the refused modify moved {volume_id} to state {refused['State']!r}, expected 'available'"
    )

    # A never-modified volume raises NotFound here rather than returning an empty list.
    mod_code, mod_message = _error_of(
        lambda: ec2.describe_volumes_modifications(VolumeIds=[volume_id]))
    assert mod_code == ERR_NO_MODIFICATION, (
        f"DescribeVolumesModifications for {volume_id} after the refusal answered {mod_code!r}: "
        f"{mod_message!r}; expected exactly {ERR_NO_MODIFICATION!r} — a refused ModifyVolume must "
        f"leave no modification record behind"
    )
    assert mod_message == f"Modification for volume '{volume_id}' does not exist.", (
        f"DescribeVolumesModifications NotFound message for {volume_id}: {mod_message!r}"
    )

    accepted = ec2.modify_volume(VolumeId=volume_id, VolumeType="gp3",
                                 MultiAttachEnabled=False)["VolumeModification"]
    assert accepted["TargetVolumeType"] == "gp3", (
        f"the accepted modification targets VolumeType {accepted['TargetVolumeType']!r}, expected "
        f"'gp3'"
    )
    assert accepted["TargetMultiAttachEnabled"] is False, (
        f"the accepted modification targets MultiAttachEnabled "
        f"{accepted['TargetMultiAttachEnabled']!r}, expected False"
    )
    assert accepted["OriginalMultiAttachEnabled"] is True, (
        f"the accepted modification reports OriginalMultiAttachEnabled "
        f"{accepted['OriginalMultiAttachEnabled']!r}, expected True — it is not describing the "
        f"volume the break was refused on"
    )

    settled = _poll_until(
        lambda: _modifications(ctx, volume_id),
        lambda mods: bool(mods) and mods[0]["ModificationState"] in ("optimizing", "completed"),
        timeout_s=300, interval_s=5,
        description=f"the accepted modification of {volume_id} leaves 'modifying'")
    assert settled[0]["TargetVolumeType"] == "gp3", (
        f"the settled modification record for {volume_id} targets "
        f"{settled[0]['TargetVolumeType']!r}, expected 'gp3'; record was {settled[0]!r}"
    )

    final = _poll_until(
        lambda: _describe_volume(ctx, volume_id),
        lambda v: v["VolumeType"] == "gp3" and v.get("MultiAttachEnabled") is False,
        timeout_s=300, interval_s=5,
        description=f"volume {volume_id} becomes gp3 with Multi-Attach cleared")
    assert final["Size"] == SIZE_GIB, (
        f"the retyped volume {volume_id} reports Size {final['Size']!r}, expected {SIZE_GIB} — the "
        f"control was supposed to change the type and the flag, nothing else"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
