"""op-contract-modify-transit-gateway-vpc-attachment."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-transit-gateway-vpc-attachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGatewayVpcAttachment adds a second subnet, which the attachment then lists; an
    unknown attachment id fails with InvalidTransitGatewayAttachmentID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"] if z["State"] == "available"]
    if len(azs) < 2:
        raise AssertionError("unreachable: region has fewer than 2 available AZs for a second attached subnet")

    tgw_name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=tgw_name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )

    vpc_name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet1_name = ctx.unique_name("sim2real-subnet1-")
    subnet1 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.1.0/24",
        AvailabilityZone=azs[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet1_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet1))
    subnet2_name = ctx.unique_name("sim2real-subnet2-")
    subnet2 = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.77.2.0/24",
        AvailabilityZone=azs[1],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet2_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet2))

    att_name = ctx.unique_name("sim2real-tgw-att-")
    att_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet1],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": att_name}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment_and_wait(ec2, att_id))
    _poll_until(lambda: _describe_att(ec2, att_id), lambda a: a["State"] == "available", timeout_s=240)

    resp = ec2.modify_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=att_id, AddSubnetIds=[subnet2])
    updated = resp["TransitGatewayVpcAttachment"]
    assert set(updated["SubnetIds"]) == {subnet1, subnet2}, updated
    after_modify = _poll_until(lambda: _describe_att(ec2, att_id), lambda a: a["State"] == "available", timeout_s=240)
    assert set(after_modify["SubnetIds"]) == {subnet1, subnet2}, after_modify

    code, message = _error(
        lambda: ec2.modify_transit_gateway_vpc_attachment(
            TransitGatewayAttachmentId="tgw-attach-00000000000000000", AddSubnetIds=[subnet2]
        )
    )
    assert code == "InvalidTransitGatewayAttachmentID.NotFound", f"unexpected error code: {code}"
    assert message == (
        "Transit Gateway VPC Attachment tgw-attach-00000000000000000 was deleted or does not exist."
    ), message


# ===== helpers =====
def _describe_att(ec2, att_id):
    return ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[att_id])[
        "TransitGatewayVpcAttachments"
    ][0]


def _delete_attachment_and_wait(ec2, att_id, timeout_s=180.0, interval_s=2.0):
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=att_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        try:
            state = _describe_att(ec2, att_id)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
            return
        if state == "deleted":
            return
        time.sleep(interval_s)
    raise AssertionError(f"attachment {att_id} still {state!r} {timeout_s:.0f}s after delete")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
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
