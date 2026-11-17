"""create-vpc-amazon-ipv6-with-explicit-ipv6-cidr-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-vpc-amazon-ipv6-with-explicit-ipv6-cidr-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateVpc rejects AmazonProvidedIpv6CidrBlock=True combined with an explicit
    Ipv6CidrBlock -- the two name conflicting sources for the same block -- and creates
    no VPC, while AmazonProvidedIpv6CidrBlock=True alone succeeds with an Amazon-assigned block.
    """
    ec2 = ctx.client("ec2")
    marker = ctx.unique_name("sim2real-ipv6src-")

    code, message = _error(lambda: ec2.create_vpc(
        CidrBlock="10.90.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        Ipv6CidrBlock="2001:db8::/56",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": marker}]}],
    ))
    assert code == "InvalidParameterCombination", (
        f"expected InvalidParameterCombination, got {code!r} ({message!r})"
    )
    assert message == (
        "The parameter 'amazonProvidedIpv6CidrBlock' may not be used in combination with "
        "'ipv6CidrBlock'."
    ), f"unexpected rejection message: {message!r}"

    leaked = ec2.describe_vpcs(Filters=[{"Name": "tag:Name", "Values": [marker]}])["Vpcs"]
    assert leaked == [], f"the rejected CreateVpc call created a VPC anyway: {leaked!r}"

    # Positive control: AmazonProvidedIpv6CidrBlock alone, with no explicit Ipv6CidrBlock, succeeds.
    vpc = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": marker}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    assert vpc.get("Ipv6CidrBlockAssociationSet"), (
        f"expected an Amazon-assigned IPv6 block on the control VPC, got {vpc!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
