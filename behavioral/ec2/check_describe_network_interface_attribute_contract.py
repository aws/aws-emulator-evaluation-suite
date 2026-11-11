"""describe-network-interface-attribute-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-network-interface-attribute-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeNetworkInterfaceAttribute: success contract (sourceDestCheck attribute + DryRun)
    against a real ENI, and NotFound on a well-formed but nonexistent network interface ID."""
    ec2 = ctx.client("ec2")
    subnet_id = _create_or_adopt_subnet(ctx)

    eni_id = ec2.create_network_interface(
        SubnetId=subnet_id,
        TagSpecifications=[
            {
                "ResourceType": "network-interface",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eni-")}],
            }
        ],
    )["NetworkInterface"]["NetworkInterfaceId"]
    ctx.on_cleanup(lambda: ec2.delete_network_interface(NetworkInterfaceId=eni_id))

    resp = ec2.describe_network_interface_attribute(
        NetworkInterfaceId=eni_id, Attribute="sourceDestCheck"
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]
    assert resp["NetworkInterfaceId"] == eni_id, (
        f"expected NetworkInterfaceId {eni_id!r}, got {resp['NetworkInterfaceId']!r}"
    )
    # A newly created (non-NAT-gateway) ENI defaults to source/dest checking enabled.
    assert resp["SourceDestCheck"]["Value"] is True, (
        f"expected SourceDestCheck.Value True on a fresh ENI, got {resp['SourceDestCheck']!r}"
    )

    _assert_dry_run_ok(
        lambda: ec2.describe_network_interface_attribute(
            NetworkInterfaceId=eni_id, Attribute="sourceDestCheck", DryRun=True
        )
    )

    bogus_eni = "eni-0123456789abcdef0"
    code, message = _error(
        lambda: ec2.describe_network_interface_attribute(
            NetworkInterfaceId=bogus_eni, Attribute="sourceDestCheck"
        )
    )
    assert code == "InvalidNetworkInterfaceID.NotFound", (
        f"expected InvalidNetworkInterfaceID.NotFound, got {code!r}"
    )
    expected = f"The networkInterface ID '{bogus_eni}' does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


def _create_or_adopt_subnet(ctx) -> str:
    """A subnet with spare IP capacity in the shared network, avoiding the VPC-per-region quota."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    for vpc in vpcs:
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        for subnet in subnets:
            if subnet.get("AvailableIpAddressCount", 0) > 0:
                return subnet["SubnetId"]

    name = ctx.unique_name("sim2real-eni-net-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.79.0.0/28",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return subnet_id


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, call unexpectedly succeeded: {result!r}")


def _assert_dry_run_ok(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
        assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
        return
    raise AssertionError("expected DryRunOperation error, call unexpectedly succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
