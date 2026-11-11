"""op-contract-delete-route."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-route"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteRoute removes the 0.0.0.0/0 route from a route table; deleting it again and deleting a
    never-routed CIDR fail with InvalidRoute.NotFound and the exact message naming CIDR and table."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-route-")

    # The check owns the VPC and the internet gateway the route points at.
    vpc_id = ec2.create_vpc(CidrBlock="10.86.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    igw_id = ec2.create_internet_gateway(TagSpecifications=[_tag_spec("internet-gateway", name)])[
        "InternetGateway"
    ]["InternetGatewayId"]

    def _cleanup_igw():
        _cleanup_ignore_error(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _cleanup_ignore_error(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))

    ctx.on_cleanup(_cleanup_igw)
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    rtb_id = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table", name)])[
        "RouteTable"
    ]["RouteTableId"]
    ctx.on_cleanup(lambda: _cleanup_ignore_error(lambda: ec2.delete_route_table(RouteTableId=rtb_id)))

    ec2.create_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    def _routes():
        return ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0]["Routes"]

    before = [r for r in _routes() if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert len(before) == 1, f"route not created: {_routes()}"

    ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0")

    after = [r for r in _routes() if r.get("DestinationCidrBlock") == "0.0.0.0/0"]
    assert after == [], f"route still present after delete: {after}"

    code, message = _error(lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="0.0.0.0/0"))
    assert code == "InvalidRoute.NotFound", f"unexpected code deleting the already-deleted route: {code}"
    assert message == f"no route with destination-cidr-block 0.0.0.0/0 in route table {rtb_id}", message

    code, message = _error(lambda: ec2.delete_route(RouteTableId=rtb_id, DestinationCidrBlock="192.0.2.0/24"))
    assert code == "InvalidRoute.NotFound", f"unexpected code deleting a never-routed CIDR: {code}"
    assert message == f"no route with destination-cidr-block 192.0.2.0/24 in route table {rtb_id}", message


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error(fn):
    """Call fn() and return its ClientError (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _cleanup_ignore_error(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "Gateway.NotAttached",
            "InvalidInternetGatewayID.NotFound",
            "InvalidRouteTableID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
