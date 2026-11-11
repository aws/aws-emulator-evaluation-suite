"""op-contract-get-transit-gateway-multicast-domain-associations."""
from __future__ import annotations

import re
import time

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-multicast-domain-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayMulticastDomainAssociations reflects a real subnet association
    through its state machine (associating -> associated); a nonexistent multicast
    domain ID is rejected as NotFound."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-tgw-"),
        Options={"MulticastSupport": "enable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _wait_tgw_state(ec2, tgw_id, {"available"})

    # Uses the run's shared network VPC; the subnet association does not need an exclusive VPC.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)

    subnet_id, _ = _create_subnet_in_vpc(ec2, vpc_id, ctx.unique_name("sim2real-tgwmc-subnet-"))
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-attach-")}]}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment(ec2, attachment_id))
    _wait_tgw_attachment_state(ec2, attachment_id, {"available"})

    domain_id = ec2.create_transit_gateway_multicast_domain(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-multicast-domain", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgwmc-domain-")}]}],
    )["TransitGatewayMulticastDomain"]["TransitGatewayMulticastDomainId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_multicast_domain(TransitGatewayMulticastDomainId=domain_id))
    # A freshly created multicast domain starts out "pending" and rejects
    # AssociateTransitGatewayMulticastDomain with IncorrectState until it settles into
    # "available" (confirmed against real AWS) -- wait for that transition first.
    _wait_tgw_multicast_domain_state(ec2, domain_id, {"available"})

    ec2.associate_transit_gateway_multicast_domain(
        TransitGatewayMulticastDomainId=domain_id,
        TransitGatewayAttachmentId=attachment_id,
        SubnetIds=[subnet_id],
    )

    def _disassociate():
        ec2.disassociate_transit_gateway_multicast_domain(
            TransitGatewayMulticastDomainId=domain_id,
            TransitGatewayAttachmentId=attachment_id,
            SubnetIds=[subnet_id],
        )
        _poll_until(
            lambda: ec2.get_transit_gateway_multicast_domain_associations(
                TransitGatewayMulticastDomainId=domain_id
            )["MulticastDomainAssociations"],
            lambda assocs: not any(a["Subnet"]["SubnetId"] == subnet_id for a in assocs),
            timeout_s=120,
            interval_s=10,
        )
    ctx.on_cleanup(_disassociate)

    # success-path contract: the subnet association reaches "associated" for the exact
    # attachment and subnet.
    assocs = _poll_until(
        lambda: ec2.get_transit_gateway_multicast_domain_associations(
            TransitGatewayMulticastDomainId=domain_id
        )["MulticastDomainAssociations"],
        lambda assocs: any(
            a["Subnet"]["SubnetId"] == subnet_id and a["Subnet"]["State"] == "associated" for a in assocs
        ),
        timeout_s=180,
        interval_s=10,
    )
    match = next(a for a in assocs if a["Subnet"]["SubnetId"] == subnet_id)
    assert match["TransitGatewayAttachmentId"] == attachment_id, (
        f"expected attachment {attachment_id}, got {match['TransitGatewayAttachmentId']}"
    )
    assert match["ResourceId"] == vpc_id, f"expected resource {vpc_id}, got {match['ResourceId']}"
    assert match["Subnet"]["State"] == "associated", f"expected state associated, got {match['Subnet']['State']}"

    # error boundary: well-formed but nonexistent multicast domain ID -> NotFound-class error.
    bogus_id = _bogus_id_like(domain_id)
    code, message = _error(lambda: ec2.get_transit_gateway_multicast_domain_associations(TransitGatewayMulticastDomainId=bogus_id))
    assert code == "InvalidTransitGatewayMulticastDomainId.NotFound", f"unexpected error code: {code!r}"
    expected = f"Transit Gateway Multicast Domain {bogus_id} was deleted or does not exist."
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
    ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
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


# A freshly created multicast domain starts out "pending" and rejects
# AssociateTransitGatewayMulticastDomain with IncorrectState until it settles into
# "available" (confirmed against real AWS); botocore ships no waiter for this
# transition, so poll the describe API's State field directly.
def _wait_tgw_multicast_domain_state(ec2, domain_id, target_states, timeout_s=300.0, interval_s=10.0):
    from botocore.exceptions import ClientError

    def probe():
        try:
            domains = ec2.describe_transit_gateway_multicast_domains(
                TransitGatewayMulticastDomainIds=[domain_id]
            )["TransitGatewayMulticastDomains"]
        except ClientError as err:
            if err.response["Error"]["Code"].endswith("NotFound"):
                return "deleted"
            raise
        return domains[0]["State"] if domains else "deleted"

    return _poll_until(probe, lambda s: s in target_states, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


