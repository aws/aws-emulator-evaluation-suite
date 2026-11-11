"""volume-attach-to-second-instance-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


def _test_ami_id(ec2):
    """Return an x86_64 HVM EBS ImageId usable for RunInstances tests."""
    strict = [
        {"Name": "state", "Values": ["available"]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "virtualization-type", "Values": ["hvm"]},
        {"Name": "root-device-type", "Values": ["ebs"]},
    ]
    attempts = [
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]}]},
        {"Owners": ["amazon"], "Filters": strict + [{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}]},
        {"Owners": ["amazon"], "Filters": strict},
        {"Owners": ["amazon"], "Filters": [{"Name": "state", "Values": ["available"]}]},
        {"Owners": ["amazon"]},
    ]
    for kw in attempts:
        try:
            images = ec2.describe_images(**kw).get("Images", [])
        except Exception:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _wait_instance_state(ec2, instance_id, state, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        reservations = resp.get("Reservations", [])
        if not reservations or not reservations[0].get("Instances"):
            last = "__not_yet_visible__"
        else:
            last = reservations[0]["Instances"][0]["State"]["Name"]
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(
        f"instance {instance_id} did not reach {state!r} within {timeout_s}s (last {last!r})"
    )


def _get_az(ec2, instance_type="t3.micro"):
    """An available AZ that actually offers *instance_type* (falls back to any)."""
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    try:
        offerings = ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
        offered = {o["Location"] for o in offerings}
        for z in zones:
            if z in offered:
                return z
    except Exception:
        pass
    return zones[0]


def _get_default_subnet(ec2, *, ctx):
    """Return (subnet_id, az) of a network subnet, preferring an AZ that offers t3.micro."""
    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
    except Exception as exc:
        raise AssertionError(f"could not list network subnets: {exc}")
    if not subnets:
        raise AssertionError("account has no network subnet for AZ-pinned launches")
    preferred = _get_az(ec2)
    chosen = next((s for s in subnets if s.get("AvailabilityZone") == preferred), subnets[0])
    return chosen["SubnetId"], chosen["AvailabilityZone"]


def _wait_volume_state(ec2, volume_id, state, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidVolume.NotFound":
                last = "__not_yet_visible__"
                time.sleep(2)
                continue
            raise
        if last == state:
            return last
        time.sleep(2)
    raise AssertionError(f"volume {volume_id} did not reach {state!r} within {timeout_s}s (last {last!r})")


def _cleanup_volume(ec2, volume_id):
    """Best-effort teardown: force-detach, wait available, delete."""
    try:
        ec2.detach_volume(VolumeId=volume_id, Force=True)
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] != "InvalidVolume.NotFound"
            and not (err["Code"] == "IncorrectState" and "is in the 'available' state" in err.get("Message", ""))
        ):
            raise
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
                raise
            return
        if state == "available":
            break
        time.sleep(2)
    try:
        ec2.delete_volume(VolumeId=volume_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVolume.NotFound":
            raise

CHECK = "volume-attach-to-second-instance-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachVolume on a volume already attached to another instance fails with VolumeInUse and
    leaves the attachment unchanged; after a detach the identical call succeeds, confirmed by an
    independent DescribeVolumes read."""
    ec2 = ctx.client("ec2")
    # Both instances must share an AZ with the volume, otherwise AttachVolume
    # would fail with InvalidVolume.ZoneMismatch instead of VolumeInUse.
    subnet_id, az = _get_default_subnet(ec2, ctx=ctx)
    ami = _test_ami_id(ec2)
    instance_a = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_a]))
    instance_b = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_b]))
    _wait_instance_state(ec2, instance_a, "running")
    _wait_instance_state(ec2, instance_b, "running")

    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")

    # positive control: a plain attach to instance_a must succeed
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_a, Device="/dev/sdf")
    _wait_volume_state(ec2, volume_id, "in-use")

    # break: attach the same volume to instance_b while it is still attached to instance_a
    try:
        accepted = ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_b, Device="/dev/sdg")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"double-attach was expected to be refused, but it SUCCEEDED: {accepted!r}")
    assert code == "VolumeInUse", f"expected VolumeInUse when double-attaching, got {code}"
    expected_message = f"{volume_id} is already attached to an instance"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect-absent: an independent read (not the mutating call's own response) proves
    # instance_b never joined the attachment and instance_a's is untouched
    attachments = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"]
    attached_instance_ids = {a["InstanceId"] for a in attachments}
    assert attached_instance_ids == {instance_a}, (
        f"after the rejected double-attach, DescribeVolumes must show only {instance_a!r} "
        f"attached to {volume_id}, got {attached_instance_ids!r}"
    )

    # restore: detach from instance_a
    ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_a)
    _wait_volume_state(ec2, volume_id, "available")

    # the identical call now succeeds
    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_b, Device="/dev/sdg")
    _wait_volume_state(ec2, volume_id, "in-use")

    # terminal read: independent, at the destination, through DescribeVolumes (not AttachVolume's
    # own response)
    attachments = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"]
    attached_instance_ids = {a["InstanceId"] for a in attachments}
    assert attached_instance_ids == {instance_b}, (
        f"after detaching from {instance_a!r} and reattaching to {instance_b!r}, "
        f"DescribeVolumes must show only {instance_b!r} attached, got {attached_instance_ids!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
