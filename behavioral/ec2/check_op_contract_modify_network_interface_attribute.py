"""op-contract-modify-network-interface-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-network-interface-attribute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyNetworkInterfaceAttribute: a Description update is observable via
    DescribeNetworkInterfaces, and specifying two attributes in one call (the API only
    allows one at a time) is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)

    name = ctx.unique_name("sim2real-behav-eni-")
    eni = ec2.create_network_interface(
        SubnetId=subnet_id,
        Description="original",
        TagSpecifications=[_tag_spec("network-interface", name)],
    )["NetworkInterface"]
    eni_id = eni["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    # success path
    ec2.modify_network_interface_attribute(
        NetworkInterfaceId=eni_id, Description={"Value": "updated-desc"}
    )
    described = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert described["Description"] == "updated-desc", described

    # error boundary: the API only accepts one attribute per call
    err, message = _error(
        lambda: ec2.modify_network_interface_attribute(
            NetworkInterfaceId=eni_id,
            Description={"Value": "double-trouble"},
            SourceDestCheck={"Value": False},
        )
    )
    assert err == "InvalidParameterCombination", err
    assert message == "Fields for multiple attribute types specified: description, sourceDestCheck", message

    # the rejected call must have had no effect: an independent read still shows the
    # description from the earlier successful update, not "double-trouble"
    after_reject = ec2.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
    assert after_reject["Description"] == "updated-desc", after_reject


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_vpc_and_subnet(ctx):
    # Prefer reusing an existing VPC/subnet (e.g. the run's shared network) to avoid
    # tripping the per-account VpcLimitExceeded quota; only create a fresh VPC/subnet
    # if nothing reusable is available.
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        for subnet in subnets:
            if subnet.get("AvailableIpAddressCount", 0) > 0:
                return vpc["VpcId"], subnet["SubnetId"]

    name = ctx.unique_name("sim2real-behav-net-")
    vpc = ec2.create_vpc(CidrBlock="10.78.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.78.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
