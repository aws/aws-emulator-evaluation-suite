"""route-creation-duplicate-destination-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-creation-duplicate-destination-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateRoute resubmitting an identical destination+target is an idempotent no-op, but pointing
    the same destination at a different target is rejected as RouteAlreadyExists, leaving the
    original route intact."""
    ec2 = ctx.client("ec2")

    def _tags(resource_type):
        return [{"ResourceType": resource_type, "Tags": [{"Key": "simparity-check", "Value": CHECK}]}]

    vpc_id = ec2.create_vpc(CidrBlock="10.172.0.0/16", TagSpecifications=_tags("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)

    igw_id = ec2.create_internet_gateway(TagSpecifications=_tags("internet-gateway"))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.172.1.0/24", TagSpecifications=_tags("subnet")
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    route_table_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tags("route-table"))[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=route_table_id))

    dest = "10.99.0.0/24"
    created = ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock=dest, GatewayId=igw_id)
    assert created["Return"] is True, f"expected the initial route to be created, got {created}"

    # Resubmitting the identical destination+target succeeds as a no-op rather than raising
    # RouteAlreadyExists.
    resubmit = ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock=dest, GatewayId=igw_id)
    assert resubmit["Return"] is True, f"expected the idempotent resubmit to succeed, got {resubmit}"

    routes = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]["Routes"]
    matching = [r for r in routes if r.get("DestinationCidrBlock") == dest]
    assert len(matching) == 1, f"idempotent resubmit should not have added a second route, got {matching}"
    assert matching[0]["GatewayId"] == igw_id

    # The real conflict: the same destination pointed at a *different*, valid target. (An invalid
    # or detached target would be rejected before the conflict is ever evaluated, which would mask
    # this behavior — so the alternate target must itself be usable.)
    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id, TagSpecifications=_tags("network-interface")
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    err = _error(
        lambda: ec2.create_route(
            RouteTableId=route_table_id, DestinationCidrBlock=dest, NetworkInterfaceId=eni_id
        )
    )
    assert err["Code"] == "RouteAlreadyExists", f"expected RouteAlreadyExists, got {err!r}"
    assert err.get("Message") == f"The route identified by {dest} already exists.", (
        f"unexpected message: {err.get('Message')!r}"
    )

    routes_after = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]["Routes"]
    matching_after = [r for r in routes_after if r.get("DestinationCidrBlock") == dest]
    assert len(matching_after) == 1, "rejected conflicting route should not have added a second route"
    assert matching_after[0]["GatewayId"] == igw_id, "the original route must remain intact after the rejected conflict"

    other_dest = "10.98.0.0/24"
    ec2.create_route(RouteTableId=route_table_id, DestinationCidrBlock=other_dest, GatewayId=igw_id)
    routes_final = ec2.describe_route_tables(RouteTableIds=[route_table_id])["RouteTables"][0]["Routes"]
    assert any(
        r.get("DestinationCidrBlock") == other_dest for r in routes_final
    ), "positive-control route creation for a different destination should have succeeded"


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
