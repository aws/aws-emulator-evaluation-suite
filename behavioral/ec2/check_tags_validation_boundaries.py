"""tags-validation-boundaries."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-validation-boundaries"
GROUP = 'tagging'
SERVICES = ['ec2']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTags accepts an ordinary tag on a real resource, but rejects a reserved
    'aws:' key and a non-existent resource id -- and neither rejection leaves a trace
    on the real resource or wedges CreateTags for a subsequent legitimate call."""
    ec2 = ctx.client("ec2")
    vpc_id = _create_vpc(ctx, "10.77.0.0/16")

    # Positive control: an ordinary tag is accepted, and independently visible via
    # DescribeTags -- a different operation than the one that mutated.
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-probe-a", "Value": "v1"}])
    _assert_tag(ec2, vpc_id, "sim2real-probe-a", "v1")

    # Break: a reserved "aws:" key is rejected outright.
    reserved_code, reserved_message = _error(
        lambda: ec2.create_tags(
            Resources=[vpc_id], Tags=[{"Key": "aws:reserved-key", "Value": "x"}]
        )
    )
    assert reserved_code == "InvalidParameterValue", (
        f"expected InvalidParameterValue, got {reserved_code}"
    )
    expected_reserved = (
        "Value ( aws:reserved-key ) for parameter key is invalid. "
        "Tag keys starting with 'aws:' are reserved for internal use"
    )
    assert reserved_message == expected_reserved, (
        f"expected message {expected_reserved!r}, got {reserved_message!r}"
    )

    # Effect absent: the rejected key never landed on the resource (independent read).
    _assert_no_tag(ec2, vpc_id, "aws:reserved-key")

    # Restore: the identical class of call (an ordinary tag on the same resource)
    # still succeeds after the rejection -- CreateTags is not wedged.
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-probe-b", "Value": "v2"}])
    _assert_tag(ec2, vpc_id, "sim2real-probe-b", "v2")

    # Empirical: CreateTags rejects an unknown VPC id with the generic "InvalidID"
    # rather than the typed InvalidVpcID.NotFound. What matters behaviorally is
    # that tagging an unknown resource is REJECTED, never silently accepted.
    unknown_code, unknown_message = _error(
        lambda: ec2.create_tags(
            Resources=["vpc-0123456789abcdef0"], Tags=[{"Key": "k", "Value": "v"}]
        )
    )
    assert unknown_code == "InvalidID", (
        f"expected InvalidID for an unknown VPC id, got {unknown_code}"
    )
    expected_unknown = "The ID 'vpc-0123456789abcdef0' is not valid"
    assert unknown_message == expected_unknown, (
        f"expected message {expected_unknown!r}, got {unknown_message!r}"
    )

    # Effect absent: the unknown-id call did not leak a tag onto the real VPC.
    _assert_no_tag(ec2, vpc_id, "k")

    # Restore: an ordinary tag on the real resource still succeeds -- a rejection
    # aimed at a different, nonexistent resource does not affect this one.
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-probe-c", "Value": "v3"}])
    _assert_tag(ec2, vpc_id, "sim2real-probe-c", "v3")

# ===== helpers =====

def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available and
    must not be turned into an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(
        f"expected a ClientError, but the call SUCCEEDED and returned {result!r}"
    )


def _assert_tag(ec2, resource_id: str, key: str, value: str) -> None:
    """Independent read (DescribeTags, not CreateTags's own response) confirming
    key=value is present on resource_id."""
    desc = ec2.describe_tags(
        Filters=[
            {"Name": "resource-id", "Values": [resource_id]},
            {"Name": "key", "Values": [key]},
        ]
    )
    found = desc.get("Tags", [])
    assert found, f"expected tag {key}={value!r} on {resource_id} via DescribeTags, found none"
    assert found[0]["Value"] == value, (
        f"expected tag {key}={value!r} on {resource_id}, "
        f"DescribeTags returned {found[0]['Value']!r}"
    )


def _assert_no_tag(ec2, resource_id: str, key: str) -> None:
    """Independent read (DescribeTags) confirming key is absent on resource_id."""
    desc = ec2.describe_tags(
        Filters=[
            {"Name": "resource-id", "Values": [resource_id]},
            {"Name": "key", "Values": [key]},
        ]
    )
    found = desc.get("Tags", [])
    assert not found, f"expected no tag {key!r} on {resource_id}, DescribeTags returned {found!r}"

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

# Marker tag attached to every resource this check creates.
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

    The default VPC quota is 5 per region and other workloads in the account may hold VPCs,
    so VpcLimitExceeded is retried until a slot frees up rather than treated as a fidelity
    signal.
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

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
