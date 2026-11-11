"""metrics-collection-toggle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "metrics-collection-toggle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableMetricsCollection populates AutoScalingGroup.EnabledMetrics and
    DisableMetricsCollection clears it again."""
    asg = ctx.client("autoscaling")
    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name)

    metrics = ["GroupMinSize", "GroupMaxSize", "GroupDesiredCapacity", "GroupInServiceInstances"]
    asg.enable_metrics_collection(
        AutoScalingGroupName=group_name, Granularity="1Minute", Metrics=metrics
    )

    enabled = _describe_group(ctx, group_name)["EnabledMetrics"]
    enabled_names = {m["Metric"] for m in enabled}
    assert enabled_names == set(metrics), f"EnabledMetrics mismatch after enable: {enabled_names}"
    assert all(m["Granularity"] == "1Minute" for m in enabled), f"unexpected granularity: {enabled}"

    asg.disable_metrics_collection(AutoScalingGroupName=group_name)

    disabled = _describe_group(ctx, group_name)["EnabledMetrics"]
    assert disabled == [], f"EnabledMetrics not cleared after DisableMetricsCollection: {disabled}"


def _describe_group(ctx, group_name: str) -> dict:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups, f"group {group_name} not found"
    return groups[0]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    return subnets[0]["SubnetId"]


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


def _create_empty_asg(ctx, name: str) -> str:
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    subnet_id = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
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
