"""op-contract-get-transit-gateway-policy-table-associations."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-policy-table-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayPolicyTableAssociations reflects a real attachment-to-policy-table
    association through its state machine (associating -> associated); a nonexistent
    policy table ID is rejected as NotFound."""
    ec2 = ctx.client("ec2")

    # A transit gateway defaults to auto-associating each new attachment with its default
    # route table (Options.DefaultRouteTableAssociation="enable"); an attachment can't hold
    # both a route-table association and a policy-table association at once, so
    # associate_transit_gateway_policy_table fails with IncorrectState ("Cannot have both
    # PolicyTableAssociation and RouteTableAssociation") unless that default association is
    # disabled at creation time (confirmed against real AWS).
    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-tgw-"),
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _wait_tgw_state(ec2, tgw_id, {"available"})

    # Uses the run's shared network VPC; the association does not need an exclusive VPC.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    subnet_id, _ = _create_subnet_in_vpc(ec2, vpc_id, ctx.unique_name("sim2real-tgwpt-subnet-"))
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwpt-attach-")}]}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment(ec2, attachment_id))
    _wait_tgw_attachment_state(ec2, attachment_id, {"available"})

    policy_table_id = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwpt-ptable-")}]}],
    )["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]

    def _delete_policy_table():
        # A policy table with an attachment association (even one still "associating")
        # refuses deletion, and the association refuses disassociation until it settles;
        # deleting the attachment first removes the association.
        _delete_attachment(ec2, attachment_id)
        ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=policy_table_id)
    ctx.on_cleanup(_delete_policy_table)
    # A freshly created policy table starts out "pending" and rejects
    # AssociateTransitGatewayPolicyTable with IncorrectState until it settles into
    # "available" (confirmed against real AWS); wait for that transition before associating.
    _wait_tgw_policy_table_state(ec2, policy_table_id, {"available"})

    ec2.associate_transit_gateway_policy_table(
        TransitGatewayPolicyTableId=policy_table_id,
        TransitGatewayAttachmentId=attachment_id,
    )

    # success-path contract: the association reaches "associated" for the exact attachment.
    assocs = _poll_until(
        lambda: ec2.get_transit_gateway_policy_table_associations(
            TransitGatewayPolicyTableId=policy_table_id
        )["Associations"],
        lambda assocs: any(a["TransitGatewayAttachmentId"] == attachment_id and a["State"] == "associated" for a in assocs),
        timeout_s=600,
        interval_s=10,
    )
    match = next(a for a in assocs if a["TransitGatewayAttachmentId"] == attachment_id)
    assert match["ResourceId"] == vpc_id
    assert match["ResourceType"] == "vpc"
    assert match["State"] == "associated"

    # error boundary: well-formed but nonexistent policy table ID -> NotFound-class error.
    bogus_id = _bogus_id_like(policy_table_id)
    code, message = _error(lambda: ec2.get_transit_gateway_policy_table_associations(TransitGatewayPolicyTableId=bogus_id))
    assert code == "InvalidTransitGatewayPolicyTableId.NotFound", f"unexpected error code: {code!r}"
    expected = f"Transit Gateway Policy Table {bogus_id} was deleted or does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _bogus_id_like(real_id: str) -> str:
    def repl(m):
        return "f" * len(m.group())
    bogus = re.sub(r"[0-9a-f]+$", repl, real_id)
    assert bogus != real_id, "could not derive a distinct bogus id"
    return bogus


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last result: {last!r}")


def _delete_attachment(ec2, attachment_id):
    """Delete the attachment and wait until it is gone; an attachment already deleting or
    deleted (a second teardown pass) is only waited on."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
    except ClientError as err:
        code = err.response["Error"]["Code"]
        if not (code.endswith("NotFound") or code == "IncorrectState"):
            raise
    _wait_tgw_attachment_state(ec2, attachment_id, {"deleted"})


def _delete_tgw(ec2, tgw_id):
    ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    _wait_tgw_state(ec2, tgw_id, {"deleted"})


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


# A freshly created policy table starts out "pending" and rejects
# AssociateTransitGatewayPolicyTable with IncorrectState until it settles into
# "available" (confirmed against real AWS); botocore ships no waiter for this
# transition, so poll the describe API's State field directly.
def _wait_tgw_policy_table_state(ec2, policy_table_id, target_states, timeout_s=300.0, interval_s=10.0):
    from botocore.exceptions import ClientError

    def probe():
        try:
            tables = ec2.describe_transit_gateway_policy_tables(
                TransitGatewayPolicyTableIds=[policy_table_id]
            )["TransitGatewayPolicyTables"]
        except ClientError as err:
            if err.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise
        return tables[0]["State"] if tables else "deleted"

    return _poll_until(probe, lambda s: s in target_states, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
