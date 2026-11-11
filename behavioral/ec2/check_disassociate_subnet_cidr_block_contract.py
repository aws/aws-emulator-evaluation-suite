"""disassociate-subnet-cidr-block-contract."""
from __future__ import annotations

import ipaddress
import time

from behavioral_harness import tags

CHECK = "disassociate-subnet-cidr-block-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateSubnetCidrBlock removes an IPv6 CIDR block from a subnet, and rejects a
    bogus association ID with the association-specific NotFound error."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(
        CidrBlock="10.216.0.0/16", AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-scbvpc-"))],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    def _vpc_ipv6():
        described = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        for assoc in described.get("Ipv6CidrBlockAssociationSet", []):
            if assoc["Ipv6CidrBlockState"]["State"] == "associated":
                return assoc["Ipv6CidrBlock"]
        return None

    vpc_ipv6_cidr = _poll_until(_vpc_ipv6, lambda c: c is not None, timeout_s=60.0, interval_s=3.0)
    assert vpc_ipv6_cidr, "VPC never received its Amazon-provided IPv6 CIDR block"

    subnet_ipv6 = next(ipaddress.ip_network(vpc_ipv6_cidr).subnets(new_prefix=64))

    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.216.1.0/24",
        TagSpecifications=[_tag_spec("subnet", ctx.unique_name("sim2real-scbsubnet-"))],
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    assoc_resp = ec2.associate_subnet_cidr_block(SubnetId=subnet_id, Ipv6CidrBlock=str(subnet_ipv6))
    assoc_id = assoc_resp["Ipv6CidrBlockAssociation"]["AssociationId"]

    def _subnet_assoc_state():
        described = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
        for assoc in described.get("Ipv6CidrBlockAssociationSet", []):
            if assoc["AssociationId"] == assoc_id:
                return assoc["Ipv6CidrBlockState"]["State"]
        return None

    assoc_state = _poll_until(_subnet_assoc_state, lambda s: s == "associated", timeout_s=60.0, interval_s=3.0)
    assert assoc_state == "associated", f"association never reached 'associated', last state: {assoc_state!r}"

    resp = ec2.disassociate_subnet_cidr_block(AssociationId=assoc_id)
    assert resp["SubnetId"] == subnet_id
    assert resp["Ipv6CidrBlockAssociation"]["AssociationId"] == assoc_id
    assert resp["Ipv6CidrBlockAssociation"]["Ipv6CidrBlockState"]["State"] in ("disassociating", "disassociated"), (
        f"expected the mutating call to report progress, got "
        f"{resp['Ipv6CidrBlockAssociation']['Ipv6CidrBlockState']['State']!r}"
    )

    # TERMINAL READ: an independent describe_subnets call, not the mutating call's own
    # response, must show the association reaching its terminal state.
    final_state = _poll_until(_subnet_assoc_state, lambda s: s == "disassociated", timeout_s=60.0, interval_s=3.0)
    assert final_state == "disassociated", (
        f"association never reached 'disassociated' via an independent read, last state: {final_state!r}"
    )

    # NEGATIVE: a bogus association ID is rejected distinctly from success.
    bogus_assoc_id = "subnet-cidr-assoc-ffffffffffffffff"
    code, message = _error(lambda: ec2.disassociate_subnet_cidr_block(AssociationId=bogus_assoc_id))
    assert code == "InvalidSubnetCidrBlockAssociationID.NotFound", f"unexpected error code for bogus association id: {code}"
    assert message == f"The subnet CIDR block with association ID '{bogus_assoc_id}' does not exist", f"unexpected message for bogus association id: {message!r}"


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


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
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
