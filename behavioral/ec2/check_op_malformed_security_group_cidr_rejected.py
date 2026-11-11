"""op-malformed-security-group-cidr-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-malformed-security-group-cidr-rejected"
GROUP = 'overly-permissive'
SERVICES = ['ec2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AuthorizeSecurityGroupIngress must reject a CIDR without prefix notation."""
    ec2 = ctx.client("ec2")
    vpc_id = _create_vpc(ctx, "10.97.0.0/16")
    gid = _create_security_group(ctx, vpc_id)

    # Positive control: an identically-shaped call with a well-formed CIDR must
    # succeed, or the malformed-CIDR rejection below is indistinguishable from a
    # target that rejects every AuthorizeSecurityGroupIngress call.
    control = ec2.authorize_security_group_ingress(
        GroupId=gid,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 8443,
                "ToPort": 8443,
                "IpRanges": [{"CidrIp": "203.0.113.5/32"}],
            }
        ],
    )
    assert control["Return"] is True, f"expected the well-formed control rule to succeed, got {control}"
    baseline = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]["IpPermissions"]
    assert baseline == [
        {
            "IpProtocol": "tcp",
            "FromPort": 8443,
            "ToPort": 8443,
            "IpRanges": [{"CidrIp": "203.0.113.5/32"}],
            "Ipv6Ranges": [],
            "PrefixListIds": [],
            "UserIdGroupPairs": [],
        }
    ], f"expected exactly the control rule after the positive control, got {baseline}"

    code, message = _error(
        lambda: ec2.authorize_security_group_ingress(
            GroupId=gid,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    # Missing "/32" -> malformed.
                    "IpRanges": [{"CidrIp": "203.0.113.5"}],
                }
            ],
        )
    )
    # Real AWS rejects a prefix-less CIDR with InvalidParameterValue (not the
    # InvalidPermission.Malformed the error table suggests).
    expected = ("InvalidParameterValue", "CIDR block 203.0.113.5 is malformed")
    assert (code, message) == expected, (
        f"expected {expected!r} for a bare IP CIDR, got {(code, message)!r}"
    )

    # The rejected call must not have changed the group's rules at all: still
    # exactly the control rule, nothing added for port 443.
    perms = ec2.describe_security_groups(GroupIds=[gid])["SecurityGroups"][0]["IpPermissions"]
    assert perms == baseline, (
        f"expected ingress rules unchanged by the rejected authorize, got {perms}"
    )

# ===== helpers =====

def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "Gateway.NotAttached",
            "InvalidAssociationID.NotFound",
            "InvalidGroup.NotFound",
            "InvalidInternetGatewayID.NotFound",
            "InvalidNetworkAclID.NotFound",
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidRouteTableID.NotFound",
            "InvalidSubnetID.NotFound",
            "NatGatewayNotFound",
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

def _create_security_group(ctx, vpc_id: str) -> str:
    ec2 = ctx.client("ec2")
    group_name = ctx.unique_name("sim2real-behav-sg-")
    gid = ec2.create_security_group(
        GroupName=group_name,
        Description="behavioral fidelity check sg",
        VpcId=vpc_id,
        TagSpecifications=_ec2_tag_specs("security-group", group_name),
    )["GroupId"]
    ctx.on_cleanup(lambda: _swallow(lambda: ec2.delete_security_group(GroupId=gid)))
    return gid

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
