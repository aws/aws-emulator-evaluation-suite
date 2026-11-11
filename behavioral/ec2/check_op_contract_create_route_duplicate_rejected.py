"""op-contract-create-route-duplicate-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-route-duplicate-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoute is idempotent for an identical destination+target, but the same CIDR toward a
    different target is rejected (RouteAlreadyExists) without touching the original route; after
    deleting the blocking route the same request succeeds."""
    ec2 = ctx.client("ec2")

    # Reuse the provided VPC and its IGW when present: a throwaway VPC risks VpcLimitExceeded.
    vpc_id, igw_id, created_vpc = _get_or_create_test_vpc(ec2, ctx)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rt-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_route_table", RouteTableId=rt_id))

    resp = ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assert resp["Return"] is True

    routes = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    matching = [r for r in routes if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(matching) == 1
    assert matching[0]["GatewayId"] == igw_id
    assert matching[0]["State"] == "active"

    # The identical destination+target is a no-op success; only a changed target conflicts.
    identical_resubmit = ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    assert identical_resubmit["Return"] is True, (
        f"expected the identical destination+target resubmission to be an idempotent no-op, "
        f"got {identical_resubmit!r}"
    )
    routes_after_resubmit = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    matching_after_resubmit = [
        r for r in routes_after_resubmit if r.get("DestinationCidrBlock") == "0.0.0.0/0"
    ]
    assert len(matching_after_resubmit) == 1, (
        f"idempotent resubmission must not duplicate the route, got {matching_after_resubmit}"
    )

    # A private NAT gateway (no EIP needed) serves as the different target for the same CIDR.
    subnet_id = _get_or_create_test_subnet(ec2, ctx, vpc_id, created_vpc)
    nat_id = ec2.create_nat_gateway(
        SubnetId=subnet_id,
        ConnectivityType="private",
        TagSpecifications=[
            {"ResourceType": "natgateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-nat-")}]}
        ],
    )["NatGateway"]["NatGatewayId"]
    ctx.on_cleanup(lambda: _delete_nat_gateway(ec2, nat_id))

    # A pending NAT gateway is rejected as InvalidNatGatewayID.NotFound when used as a route
    # target, which would mask the conflict error, so wait for "available".
    nat_state = _poll_until(
        lambda: ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert nat_state == "available", f"nat gateway ended in {nat_state!r}"

    code, message = _client_error(
        lambda: ec2.create_route(
            RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id
        )
    )
    assert code == "RouteAlreadyExists", f"expected RouteAlreadyExists, got {code!r}"
    expected_message = "The route identified by 0.0.0.0/0 already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    routes_after_conflict = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    matching_after_conflict = [
        r for r in routes_after_conflict if r.get("DestinationCidrBlock") == "0.0.0.0/0"
    ]
    assert len(matching_after_conflict) == 1, (
        f"expected exactly one route to survive the rejected conflict, got {matching_after_conflict}"
    )
    assert matching_after_conflict[0]["GatewayId"] == igw_id, (
        f"rejected conflict must leave the route on its original target, got {matching_after_conflict[0]}"
    )
    assert matching_after_conflict[0].get("NatGatewayId") is None, (
        f"rejected conflict must not have installed the NAT target, got {matching_after_conflict[0]}"
    )

    ec2.delete_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0")
    routes_after_delete = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    assert not any(r.get("DestinationCidrBlock") == "0.0.0.0/0" for r in routes_after_delete), (
        f"expected the blocking route removed before restoring, got {routes_after_delete}"
    )

    restore_resp = ec2.create_route(
        RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", NatGatewayId=nat_id
    )
    assert restore_resp["Return"] is True, (
        f"expected the identical NAT-gateway request to succeed once the conflict is cleared, "
        f"got {restore_resp!r}"
    )
    routes_final = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]["Routes"]
    matching_final = [r for r in routes_final if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(matching_final) == 1, f"expected exactly one route after restore, got {matching_final}"
    assert matching_final[0].get("NatGatewayId") == nat_id, (
        f"expected the restored route to target the NAT gateway, got {matching_final[0]}"
    )


def _get_or_create_test_vpc(ec2, ctx):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        igws = ec2.describe_internet_gateways(
            Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}]
        )["InternetGateways"]
        if igws:
            return vpc_id, igws[0]["InternetGatewayId"], False

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-igw-")}]}
        ],
    )["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_internet_gateway", InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: _delete_net(ec2, "detach_internet_gateway", InternetGatewayId=igw_id, VpcId=vpc_id))
    return vpc_id, igw_id, True


def _get_or_create_test_subnet(ec2, ctx, vpc_id, created_vpc):
    if not created_vpc:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        available = [s for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
        if available:
            return available[0]["SubnetId"]

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_id


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for the predicate; last observed {last!r}")


def _delete_nat_gateway(ec2, nat_id, *, timeout_s=180.0, interval_s=5.0):
    ec2.delete_nat_gateway(NatGatewayId=nat_id)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = ec2.describe_nat_gateways(NatGatewayIds=[nat_id])["NatGateways"][0]["State"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidNatGatewayID.NotFound":
                return
            raise
        if state == "deleted":
            return
        time.sleep(interval_s)


# AWS-managed ENIs (e.g. a NAT gateway's) leave a subnet asynchronously after their owner is
# deleted, so an immediate DeleteSubnet/DeleteVpc fails with DependencyViolation. Teardown waits
# (bounded, shared across one check's deletes) for the ENIs, retries, then names any that remain.
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
