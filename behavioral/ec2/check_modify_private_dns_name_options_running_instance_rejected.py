"""modify-private-dns-name-options-running-instance-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-private-dns-name-options-running-instance-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyPrivateDnsNameOptions on a running instance is rejected, and the same call
    succeeds once the instance is stopped."""
    ec2 = ctx.client("ec2")
    subnet_id = _shared_subnet(ctx)
    ami_id = _latest_al2023_ami(ec2)
    name = ctx.unique_name("sim2real-behav-inst-")

    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[_tag_spec("instance", name)],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ec2, instance_id))
    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )

    before = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    original_type = before["PrivateDnsNameOptions"]["HostnameType"]

    code, message = _error(
        lambda: ec2.modify_private_dns_name_options(
            InstanceId=instance_id, PrivateDnsHostnameType="resource-name"
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}: {message}"
    expected_message = "Cannot modify hostname-type for running instances"
    assert message == expected_message, f"unexpected message: {message!r}"

    # effect absent: the rejected call must not have changed the running instance's hostname type.
    unchanged = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert unchanged["PrivateDnsNameOptions"]["HostnameType"] == original_type, (
        f"a rejected ModifyPrivateDnsNameOptions must not change the hostname type, "
        f"got {unchanged['PrivateDnsNameOptions']['HostnameType']!r}"
    )

    # positive control: the identical call succeeds once the instance is stopped.
    ec2.stop_instances(InstanceIds=[instance_id])
    ec2.get_waiter("instance_stopped").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )
    ec2.modify_private_dns_name_options(InstanceId=instance_id, PrivateDnsHostnameType="resource-name")
    after = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert after["PrivateDnsNameOptions"]["HostnameType"] == "resource-name", (
        f"expected 'resource-name' after modifying a stopped instance, got {after['PrivateDnsNameOptions']}"
    )


def _terminate_and_wait(ec2, instance_id: str) -> None:
    try:
        ec2.terminate_instances(InstanceIds=[instance_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return
        raise
    ec2.get_waiter("instance_terminated").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 90}
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _shared_subnet(ctx):
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(SubnetIds=ctx.network().subnet_ids)["Subnets"]
    available = [s for s in subnets if s.get("AvailableIpAddressCount", 0) > 0]
    if not available:
        raise AssertionError(f"no subnet in {ctx.network().subnet_ids} has a free IP address")
    return available[0]["SubnetId"]


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
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
