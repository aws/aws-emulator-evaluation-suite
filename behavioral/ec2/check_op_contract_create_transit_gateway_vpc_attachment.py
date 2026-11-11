"""op-contract-create-transit-gateway-vpc-attachment."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-vpc-attachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DEFAULT_OPTIONS = {
    "DnsSupport": "enable",
    "SecurityGroupReferencingSupport": "enable",
    "Ipv6Support": "disable",
    "ApplianceModeSupport": "disable",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayVpcAttachment refuses a nonexistent subnet and a subnet of another VPC,
    creating nothing; a subnet of the VPC attaches, reaches available and describes back its VPC,
    subnet and default options."""
    ec2 = ctx.client("ec2")
    tgw_id = _create_tgw(ctx)
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, "10.44")
    other_vpc_id, other_subnet_id = _create_vpc_and_subnet(ctx, "10.45")
    _wait_tgw_available(ctx, tgw_id)

    # --- error boundary: subnet that doesn't exist ---
    absent_subnet = "subnet-00000000000000000"
    code, message = _error(
        lambda: ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[absent_subnet]
        )
    )
    assert code == "InvalidSubnetID.NotFound", f"unexpected code: {code}"
    want_message = f"The subnet ID '{absent_subnet}' does not exist"
    assert message == want_message, f"expected message {want_message!r}, got {message!r}"

    # --- error boundary: a real subnet that belongs to a different VPC ---
    foreign = _error(
        lambda: ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[other_subnet_id]
        )
    )
    want_foreign = (
        "InvalidSubnetID.NotFound",
        f"Subnet {other_subnet_id} was deleted or does not exist.",
    )
    assert foreign == want_foreign, (
        f"a subnet of {other_vpc_id} attached for {vpc_id}: expected {want_foreign!r}, got {foreign!r}"
    )
    after_refusals = _attachments(ec2, tgw_id)
    assert after_refusals == [], (
        f"the refused requests must create no attachment on {tgw_id}, got {after_refusals!r}"
    )

    # --- success path ---
    resp = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id]
    )
    att = resp["TransitGatewayVpcAttachment"]
    attach_id = att["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment(ctx, attach_id))
    assert att["TransitGatewayId"] == tgw_id, f"expected TransitGatewayId {tgw_id}, got {att['TransitGatewayId']}"
    assert att["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {att['VpcId']}"
    assert att["SubnetIds"] == [subnet_id], f"expected SubnetIds [{subnet_id}], got {att['SubnetIds']}"
    assert att["State"] == "pending", f"expected State 'pending' on create, got {att['State']!r}"

    final = _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayVpcAttachments"
        ][0],
        lambda a: a["State"] in ("available", "failed", "failing"),
        timeout_s=180.0,
    )
    final_state = final["State"]
    assert final_state == "available", f"attachment ended in {final_state}"
    echo = {
        "TransitGatewayId": final["TransitGatewayId"],
        "VpcId": final["VpcId"],
        "VpcOwnerId": final["VpcOwnerId"],
        "SubnetIds": final["SubnetIds"],
        "Options": final["Options"],
    }
    want_echo = {
        "TransitGatewayId": tgw_id,
        "VpcId": vpc_id,
        "VpcOwnerId": ctx.account,
        "SubnetIds": [subnet_id],
        "Options": _DEFAULT_OPTIONS,
    }
    assert echo == want_echo, f"DescribeTransitGatewayVpcAttachments: expected {want_echo!r}, got {echo!r}"
    listed = [a["TransitGatewayAttachmentId"] for a in _attachments(ec2, tgw_id)]
    assert listed == [attach_id], f"expected only {attach_id!r} on {tgw_id}, got {listed!r}"


# ===== helpers =====

def _error(fn: Callable[[], Any]) -> tuple:
    """Return the (code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _attachments(ec2, tgw_id: str) -> list:
    """Every VPC attachment of the gateway that is not deleted."""
    found = ec2.describe_transit_gateway_vpc_attachments(
        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
    )["TransitGatewayVpcAttachments"]
    return [a for a in found if a["State"] != "deleted"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 4.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_tgw(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    resp = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = resp["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ctx, tgw_id))
    return tgw_id


def _wait_tgw_available(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )


def _create_vpc_and_subnet(ctx, prefix: str):
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock=f"{prefix}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_vpc(ctx, vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_name = ctx.unique_name("sim2real-behav-subnet-")
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=f"{prefix}.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ctx, subnet_id))
    return vpc_id, subnet_id


def _attachment_state(ec2, attach_id: str) -> str:
    try:
        found = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayVpcAttachments"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return "deleted"
    return found[0]["State"] if found else "deleted"


def _delete_attachment(ctx, attach_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return
    final = _poll_until(
        lambda: _attachment_state(ec2, attach_id),
        lambda s: s in ("deleted", "failed"),
        timeout_s=480.0,
    )
    if final != "deleted":
        raise AssertionError(f"transit gateway attachment {attach_id} ended {final!r}, not deleted")


def _tgw_state(ec2, tgw_id: str) -> str:
    try:
        found = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise
        return "deleted"
    return found[0]["State"] if found else "deleted"


def _delete_tgw(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise
        return
    _poll_until(lambda: _tgw_state(ec2, tgw_id), lambda s: s == "deleted", timeout_s=600.0)


def _delete_subnet(ctx, subnet_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
            raise


def _delete_vpc(ctx, vpc_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        _delete_net(ec2, "delete_vpc", VpcId=vpc_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpcID.NotFound":
            raise


# AWS-managed ENIs (endpoints, load balancers, instances) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
