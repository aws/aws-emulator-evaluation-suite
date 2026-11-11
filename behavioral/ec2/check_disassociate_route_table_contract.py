"""disassociate-route-table-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-route-table-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateRouteTable detaches a subnet from a custom route table (subnet reverts
    to the VPC main route table), and a second disassociation of the same (now-gone)
    association ID is rejected with the association-specific NotFound error."""
    ec2 = ctx.client("ec2")

    # The account's VPC quota is shared with everything else running concurrently; if we're at
    # the limit, adopt a pre-existing VPC instead of failing the whole check on a capacity
    # error that has nothing to do with DisassociateRouteTable's contract.
    vpc_id = _create_or_adopt_vpc(ec2, ctx, "10.213.0.0/16", ctx.unique_name("sim2real-rtvpc-"))

    # The subnet CIDR must fall within the VPC's *actual* CIDR block(s) and must not collide
    # with any of its existing subnets. When we fell back to adopting a pre-existing VPC (VPC
    # quota reached) a hard-coded "10.213.1.0/24" has no guarantee of being inside that VPC's
    # real range, so derive an available /24 from the VPC's own CIDR block instead.
    subnet_cidr = _pick_subnet_cidr(ec2, vpc_id)

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr,
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-rtsubnet-"))],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    rtb = ec2.create_route_table(
        VpcId=vpc_id, TagSpecifications=[_tag_spec("route-table", ctx.unique_name("sim2real-rtb-"))]
    )["RouteTable"]
    rtb_id = rtb["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb_id))

    assoc_id = ec2.associate_route_table(RouteTableId=rtb_id, SubnetId=subnet_id)["AssociationId"]

    described = ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0]
    assoc_ids_before = {a.get("RouteTableAssociationId") for a in described["Associations"]}
    assert assoc_id in assoc_ids_before, "expected the new association to be visible on the route table"

    # DisassociateRouteTable's real response carries no output members (just the request
    # envelope) -- the effect is verified below via the association actually disappearing,
    # not via a "Return" flag that doesn't exist on the wire.
    ec2.disassociate_route_table(AssociationId=assoc_id)

    def _still_associated():
        described = ec2.describe_route_tables(RouteTableIds=[rtb_id])["RouteTables"][0]
        return assoc_id in {a.get("RouteTableAssociationId") for a in described["Associations"]}

    _poll_until(lambda: _still_associated(), lambda still: not still, timeout_s=60.0, interval_s=3.0)
    assert not _still_associated(), "association still present after DisassociateRouteTable"

    # NEGATIVE: the association ID no longer exists -- distinct, well-known error code.
    code, message = _error(lambda: ec2.disassociate_route_table(AssociationId=assoc_id))
    assert code == "InvalidAssociationID.NotFound", f"unexpected error code: {code}"
    assert message == f"The association ID '{assoc_id}' does not exist", f"unexpected message: {message!r}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _pick_subnet_cidr(ec2, vpc_id):
    """Return an unused /24 CIDR that actually lies within the given VPC's CIDR block(s),
    avoiding any subnets that already exist in that VPC."""
    import ipaddress

    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    vpc_cidrs = [
        assoc["CidrBlock"]
        for assoc in vpc.get("CidrBlockAssociationSet", [])
        if assoc.get("CidrBlockState", {}).get("State") == "associated"
    ]
    if not vpc_cidrs:
        vpc_cidrs = [vpc["CidrBlock"]]

    existing = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    used = [ipaddress.ip_network(s["CidrBlock"]) for s in existing]

    for vpc_cidr in vpc_cidrs:
        network = ipaddress.ip_network(vpc_cidr)
        new_prefix = max(network.prefixlen, 24)
        for candidate in network.subnets(new_prefix=new_prefix):
            if not any(candidate.overlaps(u) for u in used):
                return str(candidate)
    raise RuntimeError(f"no available /24 subnet CIDR found within VPC {vpc_id}")


def _create_or_adopt_vpc(ec2, ctx, cidr, name, exclude=None):
    """Create a fresh VPC for the test; if the account is at its VPC quota, fall back to
    adopting an already-existing VPC (distinct from ``exclude``) instead of failing the whole
    check on a capacity error unrelated to the behavior under test."""
    vpc = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
