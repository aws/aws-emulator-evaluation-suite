"""op-contract-enableTransitGatewayRouteTablePropagation."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-enableTransitGatewayRouteTablePropagation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableTransitGatewayRouteTablePropagation: a real VPC attachment can propagate into
    a real transit gateway route table + a NotFound error boundary."""
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.88.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_ignore(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.88.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_ignore(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    tgw_id = ec2.create_transit_gateway(
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=[
            {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgw-")}]}
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_ignore(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=300,
        interval_s=10,
    )

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgwa-")}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment_and_wait(ctx, attachment_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=180,
        interval_s=5,
    )

    route_table_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgwrt-")}]}
        ],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: _delete_ignore(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )

    resp = ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayAttachmentId=attachment_id, TransitGatewayRouteTableId=route_table_id
    )
    ctx.on_cleanup(
        lambda: _delete_ignore(
            lambda: ec2.disable_transit_gateway_route_table_propagation(
                TransitGatewayAttachmentId=attachment_id, TransitGatewayRouteTableId=route_table_id
            )
        )
    )
    propagation = resp["Propagation"]
    assert propagation["TransitGatewayAttachmentId"] == attachment_id, (
        f"expected attachment {attachment_id!r}, got {propagation.get('TransitGatewayAttachmentId')!r}"
    )
    assert propagation["TransitGatewayRouteTableId"] == route_table_id, (
        f"expected route table {route_table_id!r}, got {propagation.get('TransitGatewayRouteTableId')!r}"
    )
    assert propagation["State"] in ("pending", "enabled"), (
        f"expected pending/enabled immediately after enable, got {propagation.get('State')!r}"
    )

    def _probe():
        rows = ec2.get_transit_gateway_route_table_propagations(TransitGatewayRouteTableId=route_table_id)[
            "TransitGatewayRouteTablePropagations"
        ]
        matches = [r for r in rows if r.get("TransitGatewayAttachmentId") == attachment_id]
        return matches[0]["State"] if matches else None

    final_state = _poll_until(_probe, lambda s: s == "enabled", timeout_s=120, interval_s=5)
    assert final_state == "enabled", f"propagation never reached enabled, last state {final_state!r}"

    # Error boundary: enabling propagation against a nonexistent route table.
    code, message, _ = _client_error(
        lambda: ec2.enable_transit_gateway_route_table_propagation(
            TransitGatewayAttachmentId=attachment_id,
            TransitGatewayRouteTableId="tgw-rtb-00000000000000000",
        )
    )
    assert code == "InvalidRouteTableID.NotFound", f"expected InvalidRouteTableID.NotFound, got {code!r}"
    assert message == "Transit Gateway Route Table tgw-rtb-00000000000000000 was deleted or does not exist.", f"unexpected {code} message: {message!r}"


# ===== helpers =====


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_ignore(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        try:
            value = probe()
        except Exception:
            value = None
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={value!r}")


def _delete_attachment_and_wait(ctx, attachment_id: str) -> None:
    ec2 = ctx.client("ec2")
    _delete_ignore(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id))

    def _probe():
        rows = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ]
        return rows[0]["State"] if rows else "deleted"

    _poll_until(_probe, lambda s: s in ("deleted", None), timeout_s=600, interval_s=5)


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
