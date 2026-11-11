"""vpc-link-mismatched-subnet-vpcs-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "vpc-link-mismatched-subnet-vpcs-rejected"
GROUP = "representation"
SERVICES = ["apigatewayv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpcLink rejects SubnetIds drawn from two different VPCs with
    BadRequestException and creates no VpcLink, while a valid single-VPC subnet list
    still succeeds and is visible via an independent GetVpcLink read."""
    apigw = ctx.client("apigatewayv2")
    subnet_a = _create_vpc_and_subnet(ctx, "sim2real-behav-vpc-a-", "sim2real-behav-subnet-a-", "10.201.0.0/24", "10.201.0.0/28")
    subnet_b = _create_vpc_and_subnet(ctx, "sim2real-behav-vpc-b-", "sim2real-behav-subnet-b-", "10.202.0.0/24", "10.202.0.0/28")

    bad_name = ctx.unique_name("sim2real-behav-vpclink-bad-")
    code, message = _error_code(
        lambda: apigw.create_vpc_link(Name=bad_name, SubnetIds=[subnet_a, subnet_b])
    )
    assert code == "BadRequestException", (
        f"expected BadRequestException for SubnetIds drawn from two different VPCs, got {code!r}"
    )
    expected_message = "All subnets provided should be in the same VPC"
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    names_after = {item["Name"] for item in _list_all_vpc_links(apigw)}
    assert bad_name not in names_after, "a rejected CreateVpcLink call must not create a VpcLink"

    # Positive control: subnets from a single VPC succeed, verified via an independent read.
    ok_name = ctx.unique_name("sim2real-behav-vpclink-ok-")
    ok = apigw.create_vpc_link(Name=ok_name, SubnetIds=[subnet_a])
    ok_id = ok["VpcLinkId"]
    ctx.on_cleanup(lambda: _delete_vpc_link(apigw, ok_id))

    fetched = apigw.get_vpc_link(VpcLinkId=ok_id)
    assert fetched["Name"] == ok_name, f"expected VpcLink name {ok_name!r}, got {fetched['Name']!r}"
    assert fetched["SubnetIds"] == [subnet_a], (
        f"expected SubnetIds [{subnet_a!r}], got {fetched['SubnetIds']!r}"
    )


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected CreateVpcLink to be rejected, but it succeeded: {result!r}")


def _create_vpc_and_subnet(ctx, vpc_prefix: str, subnet_prefix: str, vpc_cidr: str, subnet_cidr: str) -> str:
    """Stand up a throwaway VPC + subnet, so this check does not depend on the
    account having a default VPC (a freshly provisioned account may not have one)."""
    ec2 = ctx.client("ec2")
    vpc_name = ctx.unique_name(vpc_prefix)
    vpc = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
    subnet_name = ctx.unique_name(subnet_prefix)
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": subnet_name}]}],
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return subnet_id


def _delete_vpc_link(apigw, vpc_link_id: str, timeout_s: float = 900.0) -> None:
    """A VPC link cannot be deleted while PENDING, and its network interfaces hold the subnet
    until the link is gone: wait out PENDING, delete, then wait until the link reads NotFound."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            status = apigw.get_vpc_link(VpcLinkId=vpc_link_id)["VpcLinkStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if not deleted and status not in ("PENDING", "DELETING"):
            apigw.delete_vpc_link(VpcLinkId=vpc_link_id)
            deleted = True
        time.sleep(10)
    raise AssertionError(f"VPC link {vpc_link_id} was not deleted within {timeout_s}s")


def _retry_dependency(fn, timeout_s: float = 600.0) -> None:
    """EC2 refuses to delete a subnet or VPC while released network interfaces linger."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
        time.sleep(15)


def _list_all_vpc_links(apigw):
    items = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = apigw.get_vpc_links(**kwargs)
        items.extend(resp.get("Items", []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
