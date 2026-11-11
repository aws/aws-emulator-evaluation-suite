"""network-interface-attach-detach-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-interface-attach-detach-lifecycle"
GROUP = 'network-interface'
SERVICES = ['ec2']

ERR_INVALID_PARAM = 'InvalidParameterValue'
ERR_NOT_PERMITTED = 'OperationNotPermitted'
ERR_ENI_NOT_FOUND = 'InvalidNetworkInterfaceID.NotFound'
VPC_CIDR = '10.143.0.0/16'
SUBNET_CIDR = '10.143.1.0/24'

def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _test_ami_id(ec2):
    """Return the newest x86_64 HVM EBS ImageId for RunInstances."""
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
        except ClientError:
            continue
        if not images:
            continue
        images.sort(key=lambda i: i.get("CreationDate", ""), reverse=True)
        return images[0]["ImageId"]
    raise AssertionError("could not discover a usable test AMI")


def _az_offering(ec2, instance_type):
    zones = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones().get("AvailabilityZones", [])
        if z.get("State", "available") == "available"
        and z.get("ZoneType", "availability-zone") == "availability-zone"
    ]
    if not zones:
        raise AssertionError("no availability zones available")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        ).get("InstanceTypeOfferings", [])
    }
    for z in zones:
        if z in offered:
            return z
    raise AssertionError(f"no AZ in this region offers {instance_type}")


def _wait_vpc_available(ec2, vpc_id, timeout_s=90):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last == "available":
            return
        time.sleep(2)
    raise AssertionError(f"vpc {vpc_id} never reached available in {timeout_s}s (last {last!r})")


def _wait_instance_state(ec2, instance_id, state, timeout_s=240):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        except ClientError as exc:
            if _code(exc) == "InvalidInstanceID.NotFound":
                last = "__not_yet_visible__"
                time.sleep(3)
                continue
            raise
        last = resv[0]["Instances"][0]["State"]["Name"] if resv and resv[0].get("Instances") else "__none__"
        if last == state:
            return
        time.sleep(3)
    raise AssertionError(f"instance {instance_id} never reached {state!r} in {timeout_s}s (last {last!r})")


def _eni(ec2, eni_id):
    return ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]


def _wait_eni_status(ec2, eni_id, status, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _eni(ec2, eni_id)["Status"]
        if last == status:
            return
        time.sleep(3)
    raise AssertionError(f"eni {eni_id} never reached status {status!r} in {timeout_s}s (last {last!r})")


def _wait_attachment_status(ec2, eni_id, status, timeout_s=180):
    """Poll Attachment.Status, which settles separately from the ENI's own Status.

    The ENI reads 'in-use' as soon as the attachment exists, while it is still 'attaching'.
    """
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = (_eni(ec2, eni_id).get("Attachment") or {}).get("Status")
        if last == status:
            return
        time.sleep(3)
    raise AssertionError(
        f"eni {eni_id} attachment never reached Status {status!r} in {timeout_s}s (last {last!r})"
    )


def _terminate_and_wait(ec2, instance_id, timeout_s=420):
    """Terminate and wait for 'terminated'.

    Until then the instance keeps its primary ENI in the subnet, blocking the subnet/VPC deletes."""
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resv = ec2.describe_instances(InstanceIds=[instance_id]).get("Reservations", [])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            return
        if not resv or not resv[0].get("Instances"):
            return
        if resv[0]["Instances"][0]["State"]["Name"] == "terminated":
            return
        time.sleep(5)


def _detach_and_delete_eni(ec2, eni_id):
    """Best-effort teardown: force-detach if attached, wait 'available', delete."""
    try:
        att = _eni(ec2, eni_id).get("Attachment")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise
        return
    if att:
        try:
            ec2.detach_network_interface(AttachmentId=att["AttachmentId"], Force=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidAttachmentID.NotFound":
                raise
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                if _eni(ec2, eni_id)["Status"] == "available":
                    break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
                    raise
                return
            time.sleep(3)
    try:
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A secondary ENI attaches at DeviceIndex 1, cannot be deleted while attached, detaches to
    'available' and deletes (then NotFound); the instance's primary ENI can never be detached.
    """
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": "1"}]
    instance_type = "t3.micro"
    az = _az_offering(ec2, instance_type)

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SUBNET_CIDR, AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    instance = ec2.run_instances(
        ImageId=_test_ami_id(ec2), InstanceType=instance_type, MinCount=1, MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": tag}],
    )["Instances"][0]
    instance_id = instance["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    _wait_instance_state(ec2, instance_id, "running")

    running = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    primary_nics = [n for n in running["NetworkInterfaces"] if n["Attachment"]["DeviceIndex"] == 0]
    assert len(primary_nics) == 1, f"expected exactly one DeviceIndex-0 ENI, got {running['NetworkInterfaces']}"
    primary_attachment_id = primary_nics[0]["Attachment"]["AttachmentId"]

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, Description="sim2real secondary eni",
        TagSpecifications=[{"ResourceType": "network-interface", "Tags": tag}],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: _detach_and_delete_eni(ec2, eni_id))
    fresh = _eni(ec2, eni_id)
    assert fresh["Status"] == "available", f"a new ENI must be 'available', got {fresh['Status']!r}"
    assert "Attachment" not in fresh, f"a new ENI must carry no Attachment, got {fresh.get('Attachment')}"

    attachment_id = ec2.attach_network_interface(
        NetworkInterfaceId=eni_id, InstanceId=instance_id, DeviceIndex=1
    )["AttachmentId"]
    assert attachment_id.startswith("eni-attach-"), (
        f"expected an eni-attach- attachment id, got {attachment_id!r}"
    )
    _wait_eni_status(ec2, eni_id, "in-use")
    # 'in-use' appears while the attachment itself is still 'attaching'.
    _wait_attachment_status(ec2, eni_id, "attached")
    attached = _eni(ec2, eni_id)
    assert attached["Status"] == "in-use", (
        f"an attached ENI must report interface Status 'in-use', got {attached['Status']!r}"
    )
    assert attached["Attachment"]["AttachmentId"] == attachment_id, (
        f"DescribeNetworkInterfaces reports AttachmentId "
        f"{attached['Attachment']['AttachmentId']!r} but AttachNetworkInterface returned "
        f"{attachment_id!r}; the attachment id must be stable and addressable"
    )
    assert attached["Attachment"]["InstanceId"] == instance_id, (
        f"attachment points at {attached['Attachment']['InstanceId']!r}, expected {instance_id}"
    )
    assert attached["Attachment"]["DeviceIndex"] == 1, (
        f"expected DeviceIndex 1, got {attached['Attachment']['DeviceIndex']}"
    )
    assert attached["Attachment"]["Status"] == "attached", (
        f"expected attachment Status 'attached', got {attached['Attachment']['Status']!r}"
    )

    try:
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as exc:
        assert _code(exc) == ERR_INVALID_PARAM, (
            f"expected {ERR_INVALID_PARAM} deleting an attached ENI, got {_code(exc)}"
        )
        message = exc.response["Error"]["Message"]
        assert message == f"Network interface '{eni_id}' is currently in use.", (
            f"DeleteNetworkInterface on attached {eni_id} refusal message: {message!r}"
        )
    else:
        raise AssertionError(f"DeleteNetworkInterface on attached {eni_id} must be rejected, it succeeded")
    assert _eni(ec2, eni_id)["Status"] == "in-use", "a rejected delete must leave the ENI in-use"

    try:
        ec2.detach_network_interface(AttachmentId=primary_attachment_id)
    except ClientError as exc:
        assert _code(exc) == ERR_NOT_PERMITTED, (
            f"expected {ERR_NOT_PERMITTED} detaching the primary ENI, got {_code(exc)}"
        )
        message = exc.response["Error"]["Message"]
        assert message == (
            "The network interface at device index 0 and networkCard index 0 cannot be detached."
        ), f"DetachNetworkInterface on the primary attachment refusal message: {message!r}"
    else:
        raise AssertionError(
            f"DetachNetworkInterface on the primary attachment {primary_attachment_id} must be rejected"
        )
    still = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert [n for n in still["NetworkInterfaces"] if n["Attachment"]["DeviceIndex"] == 0], (
        "the rejected primary detach must leave eth0 attached"
    )

    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=eni_id, Description={"Value": "sim2real modified"}
    )
    desc = ec2.describe_network_interface_attribute(
        NetworkInterfaceId=eni_id, Attribute="description"
    )["Description"]["Value"]
    assert desc == "sim2real modified", f"expected the modified description back, got {desc!r}"

    ec2.detach_network_interface(AttachmentId=attachment_id)
    _wait_eni_status(ec2, eni_id, "available")
    assert "Attachment" not in _eni(ec2, eni_id), "a detached ENI must expose no Attachment"
    ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    try:
        _eni(ec2, eni_id)
    except ClientError as exc:
        assert _code(exc) == ERR_ENI_NOT_FOUND, (
            f"expected {ERR_ENI_NOT_FOUND} after deleting {eni_id}, got {_code(exc)}"
        )
        message = exc.response["Error"]["Message"]
        assert message == f"The networkInterface ID '{eni_id}' does not exist", (
            f"DescribeNetworkInterfaces message for deleted {eni_id}: {message!r}"
        )
    else:
        raise AssertionError(f"deleted ENI {eni_id} is still describable")

    try:
        ec2.delete_network_interface(NetworkInterfaceId=eni_id)
    except ClientError as exc:
        assert _code(exc) == ERR_ENI_NOT_FOUND, (
            f"expected {ERR_ENI_NOT_FOUND} deleting the already-deleted {eni_id}, got {_code(exc)}"
        )
        message = exc.response["Error"]["Message"]
        assert message == f"The networkInterface ID '{eni_id}' does not exist", (
            f"DeleteNetworkInterface message for deleted {eni_id}: {message!r}"
        )
    else:
        raise AssertionError(f"a second DeleteNetworkInterface on dead {eni_id} must not succeed")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
