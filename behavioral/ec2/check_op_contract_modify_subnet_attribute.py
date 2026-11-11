"""op-contract-modify-subnet-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-subnet-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifySubnetAttribute: enabling MapPublicIpOnLaunch is observable via
    DescribeSubnets, and specifying two attributes in one call (the API only allows one
    at a time) is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)

    described = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    initial = described["MapPublicIpOnLaunch"]

    # success path: flip the attribute and confirm the change is observable via
    # DescribeSubnets.
    target = not initial
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": target})
    after = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert after["MapPublicIpOnLaunch"] is target, after

    # restore the original value so the subnet is left as found
    ctx.on_cleanup(
        lambda: ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": initial})
    )

    # error boundary: only one attribute may be modified per call
    err, err_msg = _client_error(
        lambda: ec2.modify_subnet_attribute(
            SubnetId=subnet_id,
            MapPublicIpOnLaunch={"Value": False},
            AssignIpv6AddressOnCreation={"Value": True},
        )
    )
    assert err == "InvalidParameterCombination", err
    assert err_msg == "Only one subnet attribute can be modified at a time. Provided attributes: [assignIpv6AddressOnCreation, mapPublicIpOnLaunch]", err_msg

    # effect-absent: the rejected call must not have partially applied its
    # MapPublicIpOnLaunch=False, independently re-read via DescribeSubnets
    unaffected = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert unaffected["MapPublicIpOnLaunch"] is target, unaffected


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnet(ctx):
    # A VPC and subnet of its own: the default subnets' attributes are account baseline.
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-net-")
    vpc = ec2.create_vpc(CidrBlock="10.83.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.83.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
