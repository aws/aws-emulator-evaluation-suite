"""metrics-collection-invalid-granularity-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "metrics-collection-invalid-granularity-rejected"
GROUP = "telemetry"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """EnableMetricsCollection with a granularity other than the documented-only
    valid value "1Minute" is rejected, enables nothing, and the same call with
    "1Minute" succeeds and persists."""
    autoscaling = ctx.client("autoscaling")

    _vpc_id, subnet_ids, sg_id = _default_vpc_subnets(ctx)
    ami = _al2_ami_id(ctx)

    lt_name = ctx.unique_name("sim2real-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": lt_name}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name, LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_ids[0],
        Tags=[{"Key": "Name", "Value": asg_name, "PropagateAtLaunch": False}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    code, message = _error(lambda: autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Granularity="5Minutes", Metrics=["GroupMinSize"],
    ))
    assert code == "ValidationError", (
        f"an unsupported granularity must be rejected with ValidationError, got {code!r}"
    )
    expected_message = "Valid metrics granularity type is: [1Minute]."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: nothing got enabled by the rejected call
    absent = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["EnabledMetrics"]
    assert absent == [], f"expected no EnabledMetrics after the rejected call, got {absent!r}"

    # positive control: the documented-valid granularity succeeds
    autoscaling.enable_metrics_collection(
        AutoScalingGroupName=asg_name, Granularity="1Minute", Metrics=["GroupMinSize"],
    )
    ctx.on_cleanup(lambda: autoscaling.disable_metrics_collection(AutoScalingGroupName=asg_name))
    present = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_name]
    )["AutoScalingGroups"][0]["EnabledMetrics"]
    present_metrics = {m["Metric"] for m in present}
    assert present_metrics == {"GroupMinSize"}, (
        f"expected only GroupMinSize enabled, got {present_metrics!r}"
    )
    present_granularities = {m["Granularity"] for m in present}
    assert present_granularities == {"1Minute"}, (
        f"expected Granularity=1Minute for the enabled metric, got {present_granularities!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
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
