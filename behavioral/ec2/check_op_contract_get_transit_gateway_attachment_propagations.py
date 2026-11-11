"""op-contract-get-transit-gateway-attachment-propagations."""
from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-attachment-propagations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayAttachmentPropagations reflects that a real VPC attachment
    auto-propagates into the transit gateway's default propagation route table; a
    nonexistent attachment ID is rejected as NotFound."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-tgw-"),
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _wait_tgw_state(ec2, tgw_id, {"available"})
    default_rtb_id = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0][
        "Options"
    ]["PropagationDefaultRouteTableId"]

    # Uses the run's shared network VPC; the attachment lifecycle does not need an exclusive VPC.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    subnet_id, _ = _create_subnet_in_vpc(ec2, vpc_id, ctx.unique_name("sim2real-tgwap-subnet-"))
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwap-attach-")}]}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment(ec2, attachment_id))
    _wait_tgw_attachment_state(ec2, attachment_id, {"available"})

    # success-path contract: the attachment auto-propagates into the TGW's default
    # propagation route table (DefaultRouteTablePropagation defaults to enabled).
    props = _poll_until(
        lambda: ec2.get_transit_gateway_attachment_propagations(
            TransitGatewayAttachmentId=attachment_id
        )["TransitGatewayAttachmentPropagations"],
        lambda ps: any(p["TransitGatewayRouteTableId"] == default_rtb_id and p["State"] == "enabled" for p in ps),
        timeout_s=180,
        interval_s=10,
    )
    match = next(p for p in props if p["TransitGatewayRouteTableId"] == default_rtb_id)
    assert match["State"] == "enabled", f"expected propagation state enabled, got {match['State']!r}"

    # error boundary: well-formed but nonexistent attachment ID -> NotFound-class error.
    bogus_id = _bogus_id_like(attachment_id)
    code, message = _client_error(lambda: ec2.get_transit_gateway_attachment_propagations(TransitGatewayAttachmentId=bogus_id))
    assert code == "InvalidTransitGatewayAttachmentID.NotFound", f"unexpected error code: {code}"
    expected_message = f"Transit Gateway Attachment {bogus_id} was deleted or does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _get_default_vpc(ec2, *, ctx) -> str:
    """Return the run's shared network VPC id."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    return vpcs[0]["VpcId"]


def _create_subnet_in_vpc(ec2, vpc_id: str, name_tag: str):
    """Create a subnet inside vpc_id, picking a /24 that doesn't overlap any subnet
    already there (default VPCs and any concurrently-running check may already occupy
    parts of the CIDR space, so probe candidates and retry on conflict rather than
    hardcoding one)."""
    import ipaddress
    from botocore.exceptions import ClientError

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidr = ipaddress.ip_network(vpc["CidrBlock"])
    tag_specs = [{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name_tag}]}]

    for candidate in vpc_cidr.subnets(new_prefix=24):
        cidr = str(candidate)
        try:
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=cidr, TagSpecifications=tag_specs
            )["Subnet"]["SubnetId"]
            return subnet_id, cidr
        except ClientError as err:
            if err.response["Error"]["Code"] in ("InvalidSubnet.Conflict", "InvalidSubnet.Range"):
                continue
            raise
    raise AssertionError(f"no free /24 subnet CIDR available in VPC {vpc_id} ({vpc_cidr})")


def _client_error(fn):
    """Call fn(); return its botocore error as (code, message). An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses is not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    import time
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {last!r}")


# botocore ships no waiter for transit-gateway (or its VPC attachment) create/delete
# transitions -- get_waiter("transit_gateway_available"/"...vpc_attachment_available")
# raises ValueError: Waiter does not exist (confirmed against real AWS). Poll the
# describe API's State field directly instead.
def _wait_tgw_state(ec2, tgw_id, target_states, timeout_s=600.0, interval_s=15.0):
    from botocore.exceptions import ClientError

    def probe():
        try:
            tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        except ClientError as err:
            if err.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise
        return tgws[0]["State"] if tgws else "deleted"

    return _poll_until(probe, lambda s: s in target_states, timeout_s=timeout_s, interval_s=interval_s)


def _wait_tgw_attachment_state(ec2, attachment_id, target_states, timeout_s=600.0, interval_s=15.0):
    from botocore.exceptions import ClientError

    def probe():
        try:
            atts = ec2.describe_transit_gateway_vpc_attachments(
                TransitGatewayAttachmentIds=[attachment_id]
            )["TransitGatewayVpcAttachments"]
        except ClientError as err:
            if err.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise
        return atts[0]["State"] if atts else "deleted"

    return _poll_until(probe, lambda s: s in target_states, timeout_s=timeout_s, interval_s=interval_s)


def _delete_attachment(ec2, attachment_id):
    ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
    _wait_tgw_attachment_state(ec2, attachment_id, {"deleted"})


def _delete_tgw(ec2, tgw_id):
    ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    _wait_tgw_state(ec2, tgw_id, {"deleted"})


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
