"""op-contract-describe-traffic-mirror-targets."""
from __future__ import annotations

import random
import time

from behavioral_harness import tags

CHECK = "op-contract-describe-traffic-mirror-targets"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTrafficMirrorTargets: a target created via CreateTrafficMirrorTarget
    (backed by a real ENI attached to a supported/Nitro instance) round-trips exactly
    (success contract); an unrecognized filter name is the distinct error boundary."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tmt-")
    octet = random.randint(0, 200)
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{octet}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=f"10.{octet}.0.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))
    _poll_until(
        lambda: ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]["State"],
        lambda state: state == "available",
        timeout_s=30,
        interval_s=1,
    )

    # A Traffic Mirror target's ENI must be attached to a supported (Nitro-based) instance --
    # a bare, unattached ENI is rejected with NetworkInterfaceNotSupported. Launch a minimal
    # Nitro instance (t3.micro) in the subnet and use its primary ENI as the target.
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, "no available al2023 x86_64 AMI found to launch the mirror-target instance"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    ami_id = images[0]["ImageId"]

    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Instances"][0]["InstanceId"]

    def _terminate_and_wait():
        ec2.terminate_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
        )

    ctx.on_cleanup(_terminate_and_wait)

    ec2.get_waiter("instance_running").wait(
        InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 100}
    )
    eni_id = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][
        0
    ]["NetworkInterfaces"][0]["NetworkInterfaceId"]

    description = name
    target = ec2.create_traffic_mirror_target(
        NetworkInterfaceId=eni_id,
        Description=description,
        TagSpecifications=[
            {"ResourceType": "traffic-mirror-target", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TrafficMirrorTarget"]
    target_id = target["TrafficMirrorTargetId"]
    ctx.on_cleanup(lambda: ec2.delete_traffic_mirror_target(TrafficMirrorTargetId=target_id))

    resp = ec2.describe_traffic_mirror_targets(TrafficMirrorTargetIds=[target_id])
    targets = resp["TrafficMirrorTargets"]
    assert len(targets) == 1
    assert targets[0]["TrafficMirrorTargetId"] == target_id
    assert targets[0]["NetworkInterfaceId"] == eni_id
    assert targets[0]["Description"] == description

    # Error boundary: unrecognized filter name.
    code, code_message = _error_code(
        lambda: ec2.describe_traffic_mirror_targets(
            Filters=[{"Name": "not-a-real-filter", "Values": ["x"]}]
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_code_message = "The filter 'not-a-real-filter' is invalid"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
