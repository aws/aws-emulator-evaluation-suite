"""launch-instances-creates-and-lists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-instances-creates-and-lists"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """LaunchInstances provisions instances into a group that then appear in
    DescribeAutoScalingInstances as members in the InService lifecycle state."""
    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_asg(ctx, group_name, lt_id, min_size=0, max_size=2, desired=0, subnet_id=subnet["subnet_id"])

    resp = asg.launch_instances(
        AutoScalingGroupName=group_name,
        RequestedCapacity=1,
        ClientToken=ctx.unique_name("sim2real-behav-token-"),
    )
    assert resp.get("Errors", []) == [], f"LaunchInstances reported errors: {resp.get('Errors')}"
    launched = resp.get("Instances", [])
    assert launched, "LaunchInstances returned no Instances entries"
    instance_ids: list[str] = []
    for entry in launched:
        instance_ids.extend(entry.get("InstanceIds", []))
    assert instance_ids, f"no instance IDs found in LaunchInstances response: {launched}"

    described = _poll_until(
        lambda: asg.describe_auto_scaling_instances(InstanceIds=instance_ids)["AutoScalingInstances"],
        lambda items: len(items) == len(instance_ids)
        and all(i["LifecycleState"] == "InService" for i in items),
        timeout_s=240,
        interval_s=5,
        description=f"all {len(instance_ids)} launched instances reaching InService",
    )
    assert len(described) == len(instance_ids), (
        f"expected {len(instance_ids)} instances in DescribeAutoScalingInstances, got {described}"
    )
    for inst in described:
        assert inst["AutoScalingGroupName"] == group_name, (
            f"expected AutoScalingGroupName={group_name!r}, got {inst['AutoScalingGroupName']!r}"
        )
        assert inst["LifecycleState"] == "InService", f"instance never reached InService: {inst}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    raise AssertionError(f"{description} not met within {timeout_s}s; last result: {result!r}")


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"]}


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": instance_type},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": lt_name}]}
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, min_size: int, max_size: int, desired: int, subnet_id: str, **kwargs):
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real",
                "Value": name,
                "PropagateAtLaunch": True,
            }
        ],
        **kwargs,
    )

    def _cleanup():
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
