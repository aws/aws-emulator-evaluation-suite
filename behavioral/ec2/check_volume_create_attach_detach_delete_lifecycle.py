"""volume-create-attach-detach-delete-lifecycle."""
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


def _wait_subnet_available(ec2, subnet_id, timeout_s=30):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"]
        if last == "available":
            return last
        time.sleep(2)
    raise AssertionError(f"subnet {subnet_id} did not reach 'available' within {timeout_s}s (last {last!r})")


def _get_or_create_subnet(ec2, ctx):
    """Return (subnet_id, az): reuse an existing default-for-az subnet, preferring an
    AZ that offers t3.micro; if the account has none, create a dedicated VPC/subnet
    (torn down via ctx.on_cleanup) rather than depending on an ambient shared network
    that a freshly provisioned account may not have."""
    try:
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
    except Exception as exc:
        raise AssertionError(f"could not list network subnets: {exc}")
    preferred = _get_az(ec2)
    if subnets:
        chosen = next((s for s in subnets if s.get("AvailabilityZone") == preferred), subnets[0])
        return chosen["SubnetId"], chosen["AvailabilityZone"]

    vpc_id = ec2.create_vpc(
        CidrBlock="10.211.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.211.1.0/24",
        AvailabilityZone=preferred,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    _wait_subnet_available(ec2, subnet_id)
    return subnet_id, preferred


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


def _wait_volume_attachment_state(ec2, volume_id, state, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        attachments = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0].get("Attachments", [])
        last = attachments[0]["State"] if attachments else "__none__"
        if last == state:
            return last
        time.sleep(3)
    raise AssertionError(f"volume {volume_id} attachment did not reach {state!r} within {timeout_s}s (last {last!r})")


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

CHECK = "volume-create-attach-detach-delete-lifecycle"
GROUP = 'ebs-lifecycle'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVolume(available) -> AttachVolume(in-use) -> DetachVolume(available) -> DeleteVolume(gone)."""
    ec2 = ctx.client("ec2")
    # Pin the instance to a known AZ so the volume is guaranteed co-located.
    subnet_id, az = _get_or_create_subnet(ec2, ctx)
    ami = _test_ami_id(ec2)
    instance_id = ec2.run_instances(
        ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    _wait_instance_state(ec2, instance_id, "running")

    volume_id = ec2.create_volume(AvailabilityZone=az, Size=1, TagSpecifications=[{"ResourceType": "volume", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["VolumeId"]
    ctx.on_cleanup(lambda: _cleanup_volume(ec2, volume_id))
    _wait_volume_state(ec2, volume_id, "available")

    ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    _wait_volume_state(ec2, volume_id, "in-use")
    # The volume reports 'in-use' while its attachment is still 'attaching';
    # wait for the attachment sub-state to settle before asserting on it.
    _wait_volume_attachment_state(ec2, volume_id, "attached")
    attachment = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["Attachments"][0]
    assert attachment["InstanceId"] == instance_id, (
        f"expected attachment InstanceId {instance_id!r}, got {attachment['InstanceId']!r}"
    )
    assert attachment["State"] == "attached", (
        f"expected attachment State 'attached', got {attachment['State']!r}"
    )

    ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
    _wait_volume_state(ec2, volume_id, "available")

    ec2.delete_volume(VolumeId=volume_id)

    # DeleteVolume is eventually consistent: the volume stays describable in the
    # transitional 'deleting' state before the id stops resolving entirely.
    def lookup():
        try:
            vols = ec2.describe_volumes(VolumeIds=[volume_id]).get("Volumes", [])
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        if not vols:
            return "__empty__"
        return f"__present:{vols[0]['State']}__"

    final = None
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        final = lookup()
        if not str(final).startswith("__present"):
            break
        time.sleep(5)
    gone_message = f"The volume '{volume_id}' does not exist."
    assert final in (("InvalidVolume.NotFound", gone_message), "__empty__"), (
        f"expected volume to be gone, got {final}"
    )

    # The delete must not just be reported gone by a read: an operation that
    # demonstrably worked against this same volume/instance pair earlier (DetachVolume,
    # above) must now fail against the dead id with the specific not-found code.
    dead_code = dead_message = None
    try:
        ec2.detach_volume(VolumeId=volume_id, InstanceId=instance_id)
    except ClientError as exc:
        dead_code = exc.response.get("Error", {}).get("Code")
        dead_message = exc.response.get("Error", {}).get("Message")
    assert dead_code == "InvalidVolume.NotFound", (
        f"expected DetachVolume on the deleted volume to fail InvalidVolume.NotFound, got {dead_code!r}"
    )
    assert dead_message == gone_message, f"unexpected DetachVolume message: {dead_message!r}"


# ===== helpers =====

# Instances and other ENI owners delete asynchronously, so DeleteSubnet / DeleteSecurityGroup /
# DeleteVpc can fail with DependencyViolation until their ENIs go. Wait (bounded) for the ENIs,
# retry DependencyViolation in the same window, and raise naming any ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
