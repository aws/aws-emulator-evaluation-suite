"""metrics-collection-selected-metrics-subset-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metrics-collection-selected-metrics-subset-persists"
GROUP = "telemetry"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Enabling only a named subset of metrics reports exactly that subset as
    enabled (not the full default set), partially disabling removes only the named
    ones, and disabling with no metric list clears everything."""
    autoscaling = ctx.client("autoscaling")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_ids[0],
        Tags=[
            {"Key": "sim2real", "Value": CHECK, "ResourceId": asg_name, "ResourceType": "auto-scaling-group", "PropagateAtLaunch": False}
        ],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    def enabled_metric_names():
        return {
            m["Metric"]
            for m in autoscaling.describe_auto_scaling_groups(
                AutoScalingGroupNames=[asg_name]
            )["AutoScalingGroups"][0]["EnabledMetrics"]
        }

    autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Granularity="1Minute",
        Metrics=["GroupMinSize", "GroupMaxSize"],
    )
    after_enable = enabled_metric_names()
    assert after_enable == {"GroupMinSize", "GroupMaxSize"}, (
        f"expected only the named subset enabled, got {after_enable}"
    )

    autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name, Metrics=["GroupMinSize"])
    after_partial_disable = enabled_metric_names()
    assert after_partial_disable == {"GroupMaxSize"}, (
        f"expected only GroupMaxSize to remain enabled, got {after_partial_disable}"
    )

    autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name)
    after_full_disable = enabled_metric_names()
    assert after_full_disable == set(), (
        f"expected no metrics enabled after disabling with no metric list, got {after_full_disable}"
    )


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


def _default_vpc_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    sg = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return vpc_id, [s["SubnetId"] for s in subnets], sg


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
