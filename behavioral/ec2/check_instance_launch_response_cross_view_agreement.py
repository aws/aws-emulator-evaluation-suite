"""instance-launch-response-cross-view-agreement."""
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
    """Poll DescribeInstances until the instance reaches *state* (swallows the
    eventually-consistent InvalidInstanceID.NotFound window right after launch)."""
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


CHECK = "instance-launch-response-cross-view-agreement"
GROUP = "instance-response-shape"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """One t3.micro launch: the root EBS mapping, ENI attachment, security groups and config
    option blocks carry their documented exact values, and DescribeVolumes, the primary ENI
    and DescribeInstanceAttribute(groupSet) each agree with DescribeInstances on the same facts."""
    ec2 = ctx.client("ec2")
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
        SubnetId=ctx.network().subnet_ids[0],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]

    # --- root EBS mapping, cross-checked against DescribeVolumes ---
    mappings = inst.get("BlockDeviceMappings", [])
    assert mappings, "expected non-empty BlockDeviceMappings"
    root = mappings[0]
    root_device_name = inst.get("RootDeviceName")
    assert root.get("DeviceName") == root_device_name, (
        f"expected the first BlockDeviceMappings entry's DeviceName to equal "
        f"RootDeviceName {root_device_name!r}, got {root.get('DeviceName')!r}"
    )
    ebs = root["Ebs"]
    volume_id = ebs["VolumeId"]
    assert ebs.get("Status") == "attached", f"expected Ebs.Status attached, got {ebs.get('Status')!r}"
    assert ebs.get("DeleteOnTermination") is True, (
        f"expected root volume DeleteOnTermination True, got {ebs.get('DeleteOnTermination')!r}"
    )
    assert ebs.get("AttachTime") is not None, "expected Ebs.AttachTime to be present"

    vols = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"]
    assert len(vols) == 1, f"expected DescribeVolumes to return exactly one volume, got {vols!r}"
    vol = vols[0]
    assert vol["State"] == "in-use", f"expected root volume in-use, got {vol['State']!r}"
    attachments = vol.get("Attachments", [])
    assert attachments, "expected the root volume to carry an Attachments entry"
    assert attachments[0].get("InstanceId") == instance_id, (
        f"expected DescribeVolumes Attachments[0].InstanceId to agree with the launched instance "
        f"{instance_id!r}, got {attachments[0].get('InstanceId')!r}"
    )
    assert attachments[0].get("State") == "attached", (
        f"expected DescribeVolumes Attachments[0].State attached, got {attachments[0].get('State')!r}"
    )

    # --- primary ENI attachment and private IP, cross-checked against the instance view ---
    enis = inst.get("NetworkInterfaces", [])
    assert enis, "expected non-empty NetworkInterfaces"
    primary = enis[0]
    attachment = primary.get("Attachment") or {}
    assert attachment.get("DeviceIndex") == 0, (
        f"expected primary ENI DeviceIndex 0, got {attachment.get('DeviceIndex')!r}"
    )
    assert str(attachment.get("AttachmentId", "")).startswith("eni-attach-"), (
        f"expected an eni-attach- id, got {attachment.get('AttachmentId')!r}"
    )
    assert attachment.get("DeleteOnTermination") is True, (
        f"expected primary ENI Attachment.DeleteOnTermination True, got {attachment.get('DeleteOnTermination')!r}"
    )

    private_ips = primary.get("PrivateIpAddresses", [])
    assert private_ips, "expected non-empty PrivateIpAddresses"
    assert private_ips[0].get("Primary") is True, (
        f"expected the first PrivateIpAddresses entry to be Primary, got {private_ips[0].get('Primary')!r}"
    )
    assert private_ips[0].get("PrivateIpAddress") == inst.get("PrivateIpAddress"), (
        f"expected the primary PrivateIpAddresses entry {private_ips[0].get('PrivateIpAddress')!r} "
        f"to agree with the instance's own PrivateIpAddress {inst.get('PrivateIpAddress')!r}"
    )

    # --- security groups, agreeing across the instance, its primary ENI and DescribeInstanceAttribute ---
    instance_groups = sorted((g["GroupId"], g.get("GroupName")) for g in inst.get("SecurityGroups", []))
    assert instance_groups, "expected instance SecurityGroups"
    eni_groups = sorted((g["GroupId"], g.get("GroupName")) for g in primary.get("Groups", []))
    attr = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="groupSet")
    assert attr["InstanceId"] == instance_id, (
        f"expected DescribeInstanceAttribute to echo InstanceId {instance_id!r}, got {attr['InstanceId']!r}"
    )
    attr_groups = sorted((g["GroupId"], g.get("GroupName")) for g in attr.get("Groups", []))
    assert instance_groups == eni_groups == attr_groups, (
        f"expected SecurityGroups, the primary ENI's Groups and groupSet to agree, got "
        f"instance={instance_groups!r} eni={eni_groups!r} groupSet={attr_groups!r}"
    )
    # The launch named no security group, so all three views report the VPC's default group.
    assert instance_groups[0][1] == "default", (
        f"expected the default security group, got GroupName {instance_groups[0][1]!r}"
    )

    # --- config option blocks, exact values rather than mere presence ---
    cpu = inst["CpuOptions"]
    assert cpu.get("CoreCount") == 1 and cpu.get("ThreadsPerCore") == 2, (
        f"expected t3.micro CpuOptions CoreCount=1 ThreadsPerCore=2, got {cpu!r}"
    )
    assert inst["EnclaveOptions"].get("Enabled") is False, (
        f"expected EnclaveOptions.Enabled False, got {inst['EnclaveOptions'].get('Enabled')!r}"
    )
    assert inst["HibernationOptions"].get("Configured") is False, (
        f"expected HibernationOptions.Configured False, got {inst['HibernationOptions'].get('Configured')!r}"
    )
    assert inst["PrivateDnsNameOptions"].get("HostnameType") == "ip-name", (
        f"expected PrivateDnsNameOptions.HostnameType ip-name, got "
        f"{inst['PrivateDnsNameOptions'].get('HostnameType')!r}"
    )
    assert inst["CapacityReservationSpecification"].get("CapacityReservationPreference") == "open", (
        f"expected CapacityReservationSpecification.CapacityReservationPreference open, got "
        f"{inst['CapacityReservationSpecification'].get('CapacityReservationPreference')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
