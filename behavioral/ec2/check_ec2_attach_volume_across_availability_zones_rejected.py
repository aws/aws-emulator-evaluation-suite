"""ec2-attach-volume-across-availability-zones-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-attach-volume-across-availability-zones-rejected"
GROUP = 'errors'
SERVICES = ['ec2']

INSTANCE_TYPE = 't3.micro'
AL2023_SSM = '/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64'
ERR_ZONE_MISMATCH = 'InvalidVolume.ZoneMismatch'
DATA_GIB = 1
DATA_BYTES = DATA_GIB * 1024 * 1024 * 1024

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


def _poll_until(probe, predicate, *, timeout_s, interval_s=5.0, description="condition"):
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


def _ssm_ami(ctx, parameter=AL2023_SSM):
    value = ctx.client("ssm").get_parameter(Name=parameter)["Parameter"]["Value"]
    if value.startswith("{"):
        value = json.loads(value)["image_id"]
    assert value.startswith("ami-"), f"{parameter} did not resolve to an AMI: {value!r}"
    return value


def _usable_azs(ctx, instance_type=INSTANCE_TYPE):
    ec2 = ctx.client("ec2")
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}],
    )["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, (
        f"no available AZ in {ctx.region} offers {instance_type!r}; offerings were {sorted(offered)!r}"
    )
    return usable


def _all_available_azs(ctx):
    return sorted(z["ZoneName"] for z in ctx.client("ec2").describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"])


def _default_subnet(ctx, az):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(Filters=[
        {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        {"Name": "availability-zone", "Values": [az]},
    ])["Subnets"]
    if not subnets:
        raise AssertionError(f"account has no network subnet in {az}")
    return subnets[0]["SubnetId"]


def _run_instance(ctx, *, ami, subnet_id, user_data, scenario, instance_type=INSTANCE_TYPE, **kw):
    ec2 = ctx.client("ec2")
    tags_kv = [{"Key": "sim2real", "Value": scenario}]
    return ec2.run_instances(
        ImageId=ami, InstanceType=instance_type, MinCount=1, MaxCount=1, SubnetId=subnet_id,
        UserData=user_data,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": tags_kv},
            {"ResourceType": "volume", "Tags": tags_kv},
        ],
        **kw,
    )["Instances"][0]


def _instance_state(ctx, instance_id):
    ec2 = ctx.client("ec2")
    try:
        resv = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _terminate_and_wait(ctx, instance_id, timeout_s=600):
    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if _code(exc) != "InvalidInstanceID.NotFound":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if _instance_state(ctx, instance_id) in ("terminated", "__gone__"):
            return
        time.sleep(5)


def _describe_instance_paginated(ctx, instance_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "instance-id", "Values": [instance_id]}]):
        for resv in page["Reservations"]:
            for inst in resv["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id} not found in any page of DescribeInstances")


def _create_volume(ctx, az, scenario, size_gib=DATA_GIB):
    ec2 = ctx.client("ec2")
    return ec2.create_volume(
        AvailabilityZone=az, Size=size_gib, VolumeType="gp3",
        TagSpecifications=[{"ResourceType": "volume",
                            "Tags": [{"Key": "sim2real", "Value": scenario}]}],
    )["VolumeId"]


def _describe_volume(ctx, volume_id):
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_volumes").paginate(VolumeIds=[volume_id]):
        for vol in page["Volumes"]:
            if vol["VolumeId"] == volume_id:
                return vol
    raise AssertionError(f"volume {volume_id} not found in any page of DescribeVolumes")


def _delete_volume_when_free(ctx, volume_id, timeout_s=420):
    ec2 = ctx.client("ec2")
    try:
        ec2.detach_volume(VolumeId=volume_id)
    except ClientError as exc:
        if _code(exc) not in ("IncorrectState", "InvalidVolume.NotFound"):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            return
        except ClientError as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return
            # A volume still detaching is refused as in use until the detach completes.
            if _code(exc) not in ("VolumeInUse", "IncorrectState") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _console(ctx, instance_id):
    """The instance's serial console text from GetConsoleOutput(Latest=True, required on Nitro).

    Not decoded here: botocore already base64-decodes the output in place.
    """
    resp = ctx.client("ec2").get_console_output(InstanceId=instance_id, Latest=True)
    return resp.get("Output") or ""


def _console_fields(text, marker):
    """The whitespace fields of the last console line containing marker, starting at the marker.

    Sliced at the marker because /dev/console is shared with the login getty, which prefixes lines.
    """
    for ln in reversed(text.splitlines()):
        if marker not in ln:
            continue
        parts = ln.strip().split()
        for i, p in enumerate(parts):
            if p == marker:
                return parts[i:]
    return None


def _guest_script(wait_s=900):
    """User data that reports the name and byte size of the first disk of DATA_BYTES, found by size
    via lsblk because Nitro and Xen expose different device names."""
    return (
        "#!/bin/bash\n"
        f"for i in $(seq 1 {wait_s // 3}); do\n"
        f"  LINE=$(lsblk -b -d -n -o NAME,SIZE | awk '$2 == {DATA_BYTES} {{print $1, $2; exit}}')\n"
        '  if [ -n "$LINE" ]; then echo "SIM2REAL-DISK $LINE" > /dev/console; exit 0; fi\n'
        "  sleep 3\n"
        "done\n"
        'echo "SIM2REAL-NODISK" > /dev/console\n'
    )


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """AttachVolume of a volume in another AZ is refused with InvalidVolume.ZoneMismatch and leaves no
    attachment, while a same-AZ attach succeeds and the device is visible inside the guest.

    Reference: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachVolume.html
    """
    ec2 = ctx.client("ec2")
    scenario = "ec2-attach-zone-mismatch"

    ami = _ssm_ami(ctx)
    all_azs = _all_available_azs(ctx)
    usable = _usable_azs(ctx)
    if len(all_azs) < 2:
        raise AssertionError(
            f"{ctx.region} exposes only {all_azs!r}; a cross-AZ refusal needs two zones"
        )
    az_a = usable[0]
    az_b = next(z for z in all_azs if z != az_a)
    subnet_id = _default_subnet(ctx, az_a)

    instance_id = _run_instance(ctx, ami=ami, subnet_id=subnet_id, scenario=scenario,
                                user_data=_guest_script())["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))
    _poll_until(lambda: _instance_state(ctx, instance_id), lambda s: s == "running",
                timeout_s=600, interval_s=5,
                description=f"instance {instance_id} reaches 'running' in {az_a}")
    described = _describe_instance_paginated(ctx, instance_id)
    assert described["Placement"]["AvailabilityZone"] == az_a, (
        f"the instance landed in {described['Placement']['AvailabilityZone']!r}, not the "
        f"{az_a!r} this check placed it in"
    )

    vol_b = _create_volume(ctx, az_b, scenario)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, vol_b))
    _poll_until(lambda: _describe_volume(ctx, vol_b)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"volume {vol_b} reaches 'available' in {az_b}")

    code, message = _error_of(
        lambda: ec2.attach_volume(VolumeId=vol_b, InstanceId=instance_id, Device="/dev/sdg")
    )
    assert code == ERR_ZONE_MISMATCH, (
        f"attaching {vol_b} (in {az_b}) to {instance_id} (in {az_a}) must be refused with "
        f"{ERR_ZONE_MISMATCH!r}, got {code!r}: {message!r}"
    )
    assert message == (f"The volume '{vol_b}' is not in the same availability zone as instance "
                       f"'{instance_id}'"), message

    refused = _describe_volume(ctx, vol_b)
    assert refused["State"] == "available", (
        f"after the refusal {vol_b} reports State {refused['State']!r}, expected 'available'"
    )
    assert refused["Attachments"] == [], (
        f"after the refusal {vol_b} reports Attachments {refused['Attachments']!r}, expected []"
    )
    after_refusal = _describe_instance_paginated(ctx, instance_id)
    mapped = [b["Ebs"]["VolumeId"] for b in after_refusal.get("BlockDeviceMappings", [])]
    assert vol_b not in mapped, (
        f"the refused volume {vol_b} appears in the instance's BlockDeviceMappings {mapped!r} — the "
        f"refusal did not prevent the attachment"
    )

    vol_a = _create_volume(ctx, az_a, scenario)
    ctx.on_cleanup(lambda: _delete_volume_when_free(ctx, vol_a))
    _poll_until(lambda: _describe_volume(ctx, vol_a)["State"], lambda s: s == "available",
                timeout_s=300, interval_s=5,
                description=f"volume {vol_a} reaches 'available' in {az_a}")
    ec2.attach_volume(VolumeId=vol_a, InstanceId=instance_id, Device="/dev/sdf")
    attachments = _poll_until(
        lambda: _describe_volume(ctx, vol_a)["Attachments"],
        lambda at: bool(at) and at[0]["State"] == "attached", timeout_s=300, interval_s=5,
        description=f"same-AZ volume {vol_a} reaches 'attached' on {instance_id}")
    assert len(attachments) == 1 and attachments[0]["InstanceId"] == instance_id, (
        f"the same-AZ attach must produce exactly one attachment to {instance_id!r}, got "
        f"{attachments!r}"
    )

    text = _poll_until(lambda: _console(ctx, instance_id),
                       lambda t: "SIM2REAL-DISK" in t or "SIM2REAL-NODISK" in t,
                       timeout_s=1200, interval_s=15,
                       description=f"the guest on {instance_id} reports the attached block device")
    fields = _console_fields(text, "SIM2REAL-DISK")
    assert fields is not None, (
        f"the guest never saw a {DATA_GIB} GiB block device appear after the same-AZ attach "
        f"succeeded — it reported {_console_fields(text, 'SIM2REAL-')!r}; last 2KB of console was "
        f"{text[-2048:]!r}"
    )
    assert len(fields) >= 3, (
        f"the guest's disk report must carry a device name and a byte size, got {fields!r}"
    )
    assert int(fields[2]) == DATA_BYTES, (
        f"the guest sees a device of {fields[2]!r} bytes on {fields[1]!r}, but volume {vol_a} is "
        f"{DATA_GIB} GiB = {DATA_BYTES} bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
