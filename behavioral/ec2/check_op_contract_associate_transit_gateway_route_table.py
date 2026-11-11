"""op-contract-associateTransitGatewayRouteTable."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-associateTransitGatewayRouteTable"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTransitGatewayRouteTable wires an attachment into a route table; DryRun rejects."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-tgwrt-")
    vpc = ec2.create_vpc(CidrBlock="10.196.0.0/16", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: _delete_vpc_with_retry(ec2, vpc)))
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet = ec2.create_subnet(
        VpcId=vpc, CidrBlock="10.196.1.0/24", AvailabilityZone=az,
        TagSpecifications=[_tag_spec("subnet", name)],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_subnet(SubnetId=subnet)))

    tgw = ec2.create_transit_gateway(
        Description=name,
        Options={"DefaultRouteTableAssociation": "disable"},
        TagSpecifications=[_tag_spec("transit-gateway", name)],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw)))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180,
        interval_s=5,
    )

    route_table = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw, TagSpecifications=[_tag_spec("transit-gateway-route-table", name)]
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table)
        )
    )
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=3,
    )

    attachment = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw, VpcId=vpc, SubnetIds=[subnet],
        TagSpecifications=[_tag_spec("transit-gateway-attachment", name)],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def cleanup_attachment():
        _best_effort(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment))
        _best_effort(
            lambda: _poll_until(
                lambda: _attachment_state(ec2, attachment),
                lambda s: s in ("deleted", "missing"),
                timeout_s=120,
                interval_s=5,
            )
        )

    ctx.on_cleanup(cleanup_attachment)
    _poll_until(
        lambda: _attachment_state(ec2, attachment),
        lambda s: s == "available",
        timeout_s=180,
        interval_s=5,
    )

    # error boundary: DryRun must short-circuit with DryRunOperation
    code, code_message = _error_code(
        lambda: ec2.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=route_table, TransitGatewayAttachmentId=attachment, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_code_message = "Request would have succeeded, but DryRun flag is set."
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path
    resp = ec2.associate_transit_gateway_route_table(
        TransitGatewayRouteTableId=route_table, TransitGatewayAttachmentId=attachment
    )
    assoc = resp["Association"]
    assert assoc["TransitGatewayAttachmentId"] == attachment, (
        f"expected attachment {attachment}, got {assoc['TransitGatewayAttachmentId']}"
    )
    assert assoc["TransitGatewayRouteTableId"] == route_table, (
        f"expected route table {route_table}, got {assoc['TransitGatewayRouteTableId']}"
    )
    assert assoc["State"] in ("associating", "associated"), f"unexpected association state {assoc['State']!r}"

    def cleanup_assoc():
        _best_effort(
            lambda: ec2.disassociate_transit_gateway_route_table(
                TransitGatewayRouteTableId=route_table, TransitGatewayAttachmentId=attachment
            )
        )

    ctx.on_cleanup(cleanup_assoc)

    final = _poll_until(
        lambda: [
            r
            for r in ec2.get_transit_gateway_route_table_associations(
                TransitGatewayRouteTableId=route_table
            )["Associations"]
            if r["TransitGatewayAttachmentId"] == attachment
        ],
        lambda rows: bool(rows) and rows[0]["State"] == "associated",
        timeout_s=90,
        interval_s=5,
    )
    assert final[0]["State"] == "associated", f"expected associated, got {final[0]['State']!r}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _attachment_state(ec2, attachment_id: str) -> str:
    rows = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
        "TransitGatewayVpcAttachments"
    ]
    return rows[0]["State"] if rows else "missing"


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _delete_vpc_with_retry(ec2, vpc_id: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """The VPC's own attachment/subnet ENIs can take a few seconds to release after their
    delete calls return, so an immediate DeleteVpc can see a transient DependencyViolation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpc(VpcId=vpc_id)
            return
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
