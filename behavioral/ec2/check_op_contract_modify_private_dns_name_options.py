"""op-contract-modify-private-dns-name-options."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-private-dns-name-options"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyPrivateDnsNameOptions: switching an instance's private DNS hostname type is
    observable on DescribeInstances, and a nonexistent instance id is rejected."""
    ec2 = ctx.client("ec2")
    vpc_id, subnet_id = _create_vpc_and_subnet(ctx)
    ami_id = _latest_amazon_linux_ami(ctx)
    name = ctx.unique_name("sim2real-behav-inst-")

    reservation = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[_tag_spec("instance", name)],
    )
    instance_id = reservation["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, instance_id))

    try:
        ec2.get_waiter("instance_running").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
        )
    except Exception as e:
        raise AssertionError(f"instance never reached running state: {e}")

    # Real AWS rejects a PrivateDnsHostnameType change while the instance is running
    # ("Cannot modify hostname-type for running instances"); the hostname type may
    # only be modified while the instance is stopped, so stop it first.
    ec2.stop_instances(InstanceIds=[instance_id])
    try:
        ec2.get_waiter("instance_stopped").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
        )
    except Exception as e:
        raise AssertionError(f"instance never reached stopped state: {e}")

    # success path
    ec2.modify_private_dns_name_options(
        InstanceId=instance_id,
        PrivateDnsHostnameType="resource-name",
        EnableResourceNameDnsARecord=True,
    )
    described = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    options = described["PrivateDnsNameOptions"]
    assert options["HostnameType"] == "resource-name", options
    assert options["EnableResourceNameDnsARecord"] is True, options

    # error boundary. Real AWS surfaces a nonexistent instance id on this newer,
    # non-EC2-Classic-style API as "UnknownResource" rather than the classic
    # "InvalidInstanceID.NotFound" code used by e.g. DescribeInstances.
    err, message = _error(
        lambda: ec2.modify_private_dns_name_options(
            InstanceId="i-00000000000000000", PrivateDnsHostnameType="ip-name"
        )
    )
    assert err == "UnknownResource", err
    assert message == f"User ({ctx.account}) does not own a resource i-00000000000000000 .", message


def _terminate_and_wait(ctx, instance_id: str) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )


# ===== helpers (self-contained) =====
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
    vpc = ec2.create_vpc(CidrBlock="10.79.0.0/24", TagSpecifications=[_tag_spec("vpc", name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.79.0.0/28", TagSpecifications=[_tag_spec("subnet", name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    return vpc_id, subnet_id


def _latest_amazon_linux_ami(ctx) -> str:
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-2023*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
