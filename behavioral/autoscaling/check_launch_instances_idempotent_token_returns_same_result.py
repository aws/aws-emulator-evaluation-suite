"""launch-instances-idempotent-token-returns-same-result."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-instances-idempotent-token-returns-same-result"
GROUP = "concurrency"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two LaunchInstances calls with the same ClientToken and identical params return the identical
    cached result and launch exactly one set of instances, not two."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    ami_id = _latest_al2023_ami(ctx)
    subnet = _default_subnet(ctx)
    lt_name = _create_launch_template(ctx, ami_id)
    group_name = ctx.unique_name("sim2real-asg-")

    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        MinSize=0,
        MaxSize=10,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        VPCZoneIdentifier=subnet["subnet_id"],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: _delete_group(ctx, group_name))

    token = ctx.unique_name("tok-")
    resp1 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet["subnet_id"]],
    )
    assert resp1["Errors"] == [], f"unexpected launch errors: {resp1['Errors']}"
    ids1 = sorted(
        iid for entry in resp1["Instances"] for iid in entry["InstanceIds"]
    )
    assert len(ids1) == 1, f"expected exactly 1 instance launched, got {ids1}"
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=ids1))

    resp2 = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=token,
        SubnetIds=[subnet["subnet_id"]],
    )
    assert resp2["ClientToken"] == token, (
        f"idempotent replay must echo the same ClientToken, expected {token!r} "
        f"got {resp2['ClientToken']!r}"
    )
    ids2 = sorted(
        iid for entry in resp2["Instances"] for iid in entry["InstanceIds"]
    )
    assert ids2 == ids1, (
        f"replaying the same ClientToken must return the identical instance "
        f"IDs; first={ids1} second={ids2}"
    )
    assert resp2["Errors"] == [], f"idempotent replay reported errors: {resp2['Errors']}"

    # Confirm the group actually holds exactly 1 instance -- no duplicate
    # launch happened as a side effect of the second (idempotent) call.
    count = _poll_until(
        lambda: len(
            asg.describe_auto_scaling_instances(
                InstanceIds=ids1
            )["AutoScalingInstances"]
        ),
        lambda n: n == 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert count == 1, f"expected exactly 1 tracked instance, found {count}"




def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    subnet = subnets[0]
    return {"subnet_id": subnet["SubnetId"], "az": subnet["AvailabilityZone"]}


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_group(ctx, group_name: str) -> None:
    asg = ctx.client("autoscaling")
    try:
        asg.delete_auto_scaling_group(
            AutoScalingGroupName=group_name, ForceDelete=True
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
            return
        raise
    _poll_until(
        lambda: len(
            asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[group_name]
            )["AutoScalingGroups"]
        ),
        lambda n: n == 0,
        timeout_s=90.0,
        interval_s=3.0,
    )


# Resources in this VPC delete asynchronously and leave ENIs behind, so a network delete
# waits (bounded) for them and retries DependencyViolation instead of leaking the VPC.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
