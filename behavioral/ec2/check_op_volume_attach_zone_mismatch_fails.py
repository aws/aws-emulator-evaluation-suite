"""op-volume-attach-zone-mismatch-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-volume-attach-zone-mismatch-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AttachVolume across Availability Zones is rejected, while a same-AZ attach (the positive
    control) succeeds, so a target refusing every attach cannot pass."""
    ec2 = ctx.client("ec2")
    azs = _available_azs(ec2)
    assert len(azs) >= 2, f"need >=2 AZs for this check, got {azs}"
    az_instance, az_volume = azs[0], azs[1]

    vpc_id = _create_vpc(ctx, "10.94.0.0/16")
    subnet_id = _create_subnet(ctx, vpc_id, "10.94.1.0/24", az=az_instance)

    started = ec2.run_instances(
        ImageId=_default_ami_id(ec2),
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_ec2_tag_specs("instance"),
    )
    instance_id = started["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_instance_and_wait(ec2, instance_id))
    _wait_instance_state(ec2, instance_id, "running")

    # --- positive control: an attach in the SAME AZ as the instance must succeed ---
    pos_vol = ec2.create_volume(
        AvailabilityZone=az_instance,
        Size=8,
        VolumeType="gp3",
        TagSpecifications=_ec2_tag_specs("volume"),
    )
    pos_volume_id = pos_vol["VolumeId"]
    ctx.on_cleanup(lambda: _detach_and_delete_volume(ec2, pos_volume_id))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[pos_volume_id]),
        lambda r: r["Volumes"][0]["State"] == "available",
        timeout_s=60,
        interval_s=2,
    )
    _expect_success(
        lambda: ec2.attach_volume(VolumeId=pos_volume_id, InstanceId=instance_id, Device="/dev/sdg"),
        "same-AZ AttachVolume",
    )
    attached = _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[pos_volume_id]),
        lambda r: r["Volumes"][0]["State"] == "in-use",
        timeout_s=60,
        interval_s=2,
    )["Volumes"][0]
    assert attached["Attachments"] and attached["Attachments"][0]["InstanceId"] == instance_id, (
        f"expected same-AZ volume {pos_volume_id} attached to {instance_id}, "
        f"got {attached.get('Attachments')}"
    )

    # --- break exactly one thing: the volume's availability zone ---
    vol = ec2.create_volume(
        AvailabilityZone=az_volume,
        Size=8,
        VolumeType="gp3",
        TagSpecifications=_ec2_tag_specs("volume"),
    )
    volume_id = vol["VolumeId"]
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.delete_volume(VolumeId=volume_id)))
    _poll_until(
        lambda: ec2.describe_volumes(VolumeIds=[volume_id]),
        lambda r: r["Volumes"][0]["State"] == "available",
        timeout_s=60,
        interval_s=2,
    )

    code, message = _expect_rejected(
        lambda: ec2.attach_volume(VolumeId=volume_id, InstanceId=instance_id, Device="/dev/sdf")
    )
    assert code == "InvalidVolume.ZoneMismatch", (
        f"expected InvalidVolume.ZoneMismatch for cross-AZ attach, got {code}"
    )
    expected_message = (
        f"The volume '{volume_id}' is not in the same availability zone as instance '{instance_id}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The volume must remain available (not silently attached).
    state = ec2.describe_volumes(VolumeIds=[volume_id])["Volumes"][0]["State"]
    assert state == "available", f"expected volume still available, got {state}"

# ===== helpers =====

def _expect_rejected(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises -- an emulator ACCEPTING
    input real AWS refuses is the strongest signal available and must not be turned into a
    falsy sentinel that reads as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _expect_success(fn, description: str):
    try:
        return fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(f"expected {description} to succeed, got {code}: {exc}") from exc


def _detach_and_delete_volume(ec2, volume_id: str) -> None:
    _swallow(lambda: ec2.detach_volume(VolumeId=volume_id))
    try:
        _poll_until(
            lambda: ec2.describe_volumes(VolumeIds=[volume_id]),
            lambda r: r["Volumes"][0]["State"] == "available",
            timeout_s=90,
            interval_s=3,
        )
    except AssertionError:
        pass
    _swallow(lambda: ec2.delete_volume(VolumeId=volume_id))

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("Gateway.NotAttached", "InvalidAssociationID.NotFound", "InvalidGroup.NotFound", "InvalidInstanceID.NotFound", "InvalidInternetGatewayID.NotFound", "InvalidNetworkAclID.NotFound", "InvalidNetworkInterfaceID.NotFound", "InvalidRouteTableID.NotFound", "InvalidSubnetID.NotFound", "InvalidVolume.NotFound", "NatGatewayNotFound")
            and not (err["Code"] == "IncorrectState" and "is in the 'available' state" in err.get("Message", ""))
        ):
            raise

def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")

# EC2 resources have no name-prefix based discovery, so every create call MUST
# attach this marker tag or the resource is invisible to the account's cleanup /
# sweep tooling.
_MANAGED_TAG_KEY = "sim2real-managed"
_MANAGED_TAG_VALUE = "true"


def _ec2_tag_specs(resource_type: str, name: str | None = None) -> list[dict]:
    """TagSpecifications carrying the managed-resource marker tag."""
    tags = [{"Key": _MANAGED_TAG_KEY, "Value": _MANAGED_TAG_VALUE}]
    if name:
        tags.append({"Key": "Name", "Value": name})
    return [{"ResourceType": resource_type, "Tags": tags}]

def _create_vpc(ctx, cidr: str, timeout_s: int = 420) -> str:
    """Create a VPC, waiting out per-region quota contention.

    The default VPC quota is 5 per region but checks execute concurrently against
    one shared account, so VpcLimitExceeded is a transient condition here (another
    check is about to tear its VPC down), not a fidelity signal -- retry until a
    slot frees up.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-vpc-")
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while True:
        try:
            resp = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=_ec2_tag_specs("vpc", name))
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            attempt += 1
            time.sleep(min(5 + attempt * 2, 20))

    vpc_id = resp["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _force_delete_vpc(ec2, vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id]),
        lambda r: r["Vpcs"][0]["State"] == "available",
        timeout_s=60,
        interval_s=2,
    )
    return vpc_id

def _force_delete_vpc(ec2, vpc_id: str, timeout_s: int = 240) -> None:
    """Delete a VPC, sweeping its dependencies and retrying DependencyViolation to a deadline:
    ENIs and NAT gateways of deleted resources hold its subnets for a while after they go."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidVpcID.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        _sweep_vpc_dependencies(ec2, vpc_id)
        time.sleep(2)


def _sweep_vpc_dependencies(ec2, vpc_id: str) -> None:
    """Best-effort removal of everything that can block delete_vpc."""
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]

    # VPC endpoints hold subnets/route tables.
    try:
        eps = ec2.describe_vpc_endpoints(Filters=vpc_filter)["VpcEndpoints"]
        ids = [e["VpcEndpointId"] for e in eps if e["State"] not in ("deleted", "deleting")]
        if ids:
            ec2.delete_vpc_endpoints(VpcEndpointIds=ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcEndpointId.NotFound":
            raise

    # Detached/available ENIs (instance teardown leaves these behind).
    try:
        for eni in ec2.describe_network_interfaces(Filters=vpc_filter)["NetworkInterfaces"]:
            if eni.get("Status") == "in-use":
                continue
            _swallow(lambda e=eni: ec2.delete_network_interface(NetworkInterfaceId=e["NetworkInterfaceId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkInterfaceID.NotFound":
            raise

    # NAT gateways still holding a subnet.
    try:
        for nat in ec2.describe_nat_gateways(Filters=vpc_filter)["NatGateways"]:
            if nat["State"] in ("deleted", "deleting"):
                continue
            _swallow(lambda n=nat: ec2.delete_nat_gateway(NatGatewayId=n["NatGatewayId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NatGatewayNotFound":
            raise

    # Internet gateways.
    try:
        for igw in ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]:
            igw_id = igw["InternetGatewayId"]
            _swallow(lambda i=igw_id: ec2.detach_internet_gateway(InternetGatewayId=i, VpcId=vpc_id))
            _swallow(lambda i=igw_id: ec2.delete_internet_gateway(InternetGatewayId=i))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "Gateway.NotAttached",
            "InvalidInternetGatewayID.NotFound",
        ):
            raise

    # Non-main route tables.
    try:
        for rt in ec2.describe_route_tables(Filters=vpc_filter)["RouteTables"]:
            if any(a.get("Main") for a in rt.get("Associations", [])):
                continue
            for assoc in rt.get("Associations", []):
                _swallow(
                    lambda a=assoc: ec2.disassociate_route_table(
                        AssociationId=a["RouteTableAssociationId"]
                    )
                )
            _swallow(lambda r=rt: ec2.delete_route_table(RouteTableId=r["RouteTableId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidAssociationID.NotFound",
            "InvalidRouteTableID.NotFound",
        ):
            raise

    # Non-default security groups.
    try:
        for sg in ec2.describe_security_groups(Filters=vpc_filter)["SecurityGroups"]:
            if sg["GroupName"] == "default":
                continue
            _swallow(lambda s=sg: ec2.delete_security_group(GroupId=s["GroupId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidGroup.NotFound":
            raise

    # Non-default network ACLs.
    try:
        for acl in ec2.describe_network_acls(Filters=vpc_filter)["NetworkAcls"]:
            if acl.get("IsDefault"):
                continue
            _swallow(lambda a=acl: ec2.delete_network_acl(NetworkAclId=a["NetworkAclId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidNetworkAclID.NotFound":
            raise

    # Subnets last (they depend on everything above).
    try:
        for subnet in ec2.describe_subnets(Filters=vpc_filter)["Subnets"]:
            _swallow(lambda s=subnet: ec2.delete_subnet(SubnetId=s["SubnetId"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise

def _create_subnet(ctx, vpc_id: str, cidr: str, az: str | None = None) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-subnet-")
    kwargs = {
        "VpcId": vpc_id,
        "CidrBlock": cidr,
        "TagSpecifications": _ec2_tag_specs("subnet", name),
    }
    if az:
        kwargs["AvailabilityZone"] = az
    subnet_id = ec2.create_subnet(**kwargs)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id

def _default_ami_id(ec2) -> str:
    """An Amazon-owned AL2 AMI, falling back to a well-formed placeholder id when
    DescribeImages is unavailable to the caller."""
    try:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[{"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]}],
        ).get("Images", [])
        if images:
            return images[0]["ImageId"]
    except Exception:  # noqa: BLE001
        pass
    return "ami-0123456789abcdef0"

def _available_azs(ec2) -> list[str]:
    """Names of AZs that are currently 'available' in this region."""
    resp = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    return [z["ZoneName"] for z in resp["AvailabilityZones"]]

def _wait_instance_state(ec2, instance_id: str, state: str, timeout_s: int = 300) -> None:
    """Poll until the instance reaches *state*.

    RunInstances is eventually consistent: an immediate DescribeInstances can
    raise InvalidInstanceID.NotFound for a few seconds after the instance is
    returned. Treat that as "not yet in the target state" rather than an error.
    """

    def describe():
        try:
            return ec2.describe_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return None
            raise

    def reached(resp) -> bool:
        if not resp:
            return False
        for res in resp.get("Reservations", []):
            for inst in res.get("Instances", []):
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"] == state
        return False

    _poll_until(describe, reached, timeout_s=timeout_s, interval_s=3)

def _terminate_instance_and_wait(ec2, instance_id: str, timeout_s: int = 300) -> None:
    """A running instance holds the subnet (via its ENI), so the VPC teardown that
    follows cannot complete until this instance is actually terminated -- not
    merely asked to terminate."""
    _swallow(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    try:
        _wait_instance_state(ec2, instance_id, "terminated", timeout_s=timeout_s)
    except AssertionError:
        pass

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
