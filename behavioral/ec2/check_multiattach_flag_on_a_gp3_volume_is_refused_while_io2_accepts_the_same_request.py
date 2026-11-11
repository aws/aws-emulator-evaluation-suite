"""multiattach-flag-on-a-gp3-volume-is-refused-while-io2-accepts-the-same-request."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multiattach-flag-on-a-gp3-volume-is-refused-while-io2-accepts-the-same-request"
GROUP = 'multiattach-volume-type'
SERVICES = ['ec2']

#: io2's minimum size, and the one size both halves of the comparison use: the break and the
#: control differ in VolumeType (and the Iops io2 requires), in nothing else.
SIZE_GIB = 4
IO2_IOPS = 100
ERR_BAD_COMBINATION = 'InvalidParameterCombination'


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


class _UnexpectedSuccess(Exception):
    """Raised when a call the check expects to be refused succeeds.

    Not a falsy sentinel, so an accepted request is not misread as an error-code mismatch.
    """


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
    """One AZ that is both 'available' and offers the volume types this check compares.

    EBS volume types are not offered uniformly across zones, and AZ names are per-account aliases.
    """
    ec2 = ctx.client("ec2")
    available = {z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]}
    offering = {}
    for page in ec2.get_paginator("describe_instance_type_offerings").paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": ["m5.large"]}]):
        for off in page["InstanceTypeOfferings"]:
            offering[off["Location"]] = off
    usable = sorted(available & set(offering))
    assert usable, (
        f"no available AZ in {ctx.region} offers the Nitro instance family Multi-Attach requires; "
        f"available zones were {sorted(available)!r} and offerings were {sorted(offering)!r}"
    )
    return usable[0]


def _volumes_tagged(ctx, marker):
    """Every volume carrying this run's own marker tag, paginated.

    Scoped to a tag only this invocation uses, so other volumes in the account cannot decide it.
    """
    ec2 = ctx.client("ec2")
    found = []
    for page in ec2.get_paginator("describe_volumes").paginate(
            Filters=[{"Name": "tag:sim2real-multiattach", "Values": [marker]}]):
        found.extend(page["Volumes"])
    return found


def _tag_spec(ctx, marker):
    return [{"ResourceType": "volume", "Tags": [
        {"Key": "sim2real-multiattach", "Value": marker},
        {"Key": "sim2real", "Value": "multiattach-volume-type"},
        {"Key": "Name", "Value": ctx.unique_name("sim2real-multiattach-")},
    ]}]


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


def _describe_volume(ctx, volume_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVolume with MultiAttachEnabled=True is refused with InvalidParameterCombination for gp3
    and accepted for an io2 volume of the same size in the same zone, and the refused request
    leaves no volume behind.

    Reference: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-volumes-multi.html
    """
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-multiattach-gp3-")
    az = _usable_az(ctx)

    # The marker namespace must start empty for the effect-absent assertion to mean anything.
    before = _volumes_tagged(ctx, marker)
    assert before == [], (
        f"this run's marker tag {marker!r} already matched volumes {[v['VolumeId'] for v in before]!r} "
        f"before the check created anything"
    )

    code, message = _error_of(lambda: ec2.create_volume(
        AvailabilityZone=az, Size=SIZE_GIB, VolumeType="gp3", MultiAttachEnabled=True,
        TagSpecifications=_tag_spec(ctx, marker)))
    assert code == ERR_BAD_COMBINATION, (
        f"CreateVolume(VolumeType='gp3', MultiAttachEnabled=True) in {az} must be refused with "
        f"exactly {ERR_BAD_COMBINATION!r}, got {code!r}: {message!r}"
    )
    assert message == "The parameter multi-attach-enabled is not supported for gp3 volumes.", (
        f"CreateVolume(VolumeType='gp3', MultiAttachEnabled=True) refusal message: {message!r}"
    )

    after_refusal = _volumes_tagged(ctx, marker)
    assert after_refusal == [], (
        f"the refused CreateVolume left volumes behind: "
        f"{[(v['VolumeId'], v['VolumeType'], v['State']) for v in after_refusal]!r} — the refusal "
        f"was reported but the resource exists"
    )

    control = ec2.create_volume(
        AvailabilityZone=az, Size=SIZE_GIB, VolumeType="io2", Iops=IO2_IOPS,
        MultiAttachEnabled=True, TagSpecifications=_tag_spec(ctx, marker))
    control_id = control["VolumeId"]
    ctx.on_cleanup(lambda: _delete_volume(ctx, control_id))
    assert control.get("MultiAttachEnabled") is True, (
        f"the io2 control volume {control_id} reported MultiAttachEnabled "
        f"{control.get('MultiAttachEnabled')!r} at creation, expected True — the control does not "
        f"establish that the request the gp3 volume was refused is otherwise legal"
    )
    _poll_until(lambda: _describe_volume(ctx, control_id)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=3,
                description=f"io2 Multi-Attach volume {control_id} reaches 'available'")

    described = _describe_volume(ctx, control_id)
    assert described["MultiAttachEnabled"] is True, (
        f"DescribeVolumes reports MultiAttachEnabled {described['MultiAttachEnabled']!r} for the "
        f"io2 control {control_id}, expected True — the flag was accepted at create and then lost"
    )
    assert described["VolumeType"] == "io2", (
        f"the control volume {control_id} reports VolumeType {described['VolumeType']!r}, expected "
        f"'io2'"
    )

    settled = _volumes_tagged(ctx, marker)
    assert [v["VolumeId"] for v in settled] == [control_id], (
        f"the marker namespace holds "
        f"{[(v['VolumeId'], v['VolumeType']) for v in settled]!r}, expected exactly the io2 "
        f"control {control_id!r}: the gp3 request must have created nothing and the io2 request "
        f"exactly one volume"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
