"""autoscaling-action-arn-structure-and-region-validated-before-delivery."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "autoscaling-action-arn-structure-and-region-validated-before-delivery"
GROUP = "representation"
SERVICES = ["autoscaling", "cloudwatch", "ec2", "ssm"]

_COMMON_ALARM_KWARGS: dict[str, Any] = dict(
    Namespace="AWS/EC2",
    MetricName="CPUUtilization",
    Statistic="Average",
    Period=60,
    EvaluationPeriods=1,
    Threshold=80.0,
    ComparisonOperator="GreaterThanThreshold",
)


def _reject(fn):
    """The (Code, Message) of the ClientError ``fn`` raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _retry_dependency_violation(delete_call, *, timeout_s: float = 90.0, interval_s: float = 5.0) -> None:
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete_call()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags(
    "axis:rejection",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A scalingPolicy alarm action missing its policyName segment, or naming a region other than
    the alarm's own, is rejected with its exact message; a real zero-capacity group's own policy
    ARN is accepted and round-trips verbatim.
    """
    cw = ctx.client("cloudwatch")
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.197.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [
            {"Key": "Name", "Value": ctx.unique_name("sim2real-xsvc-cwasg-")},
            {"Key": "sim2real", "Value": "autoscaling__cloudwatch"},
        ]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency_violation(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.197.1.0/24", AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "autoscaling__cloudwatch"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency_violation(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    template_name = ctx.unique_name("sim2real-xsvc-cwasg-lt-")
    # DesiredCapacity stays 0 for the group's whole life, so this AMI is never used to launch
    # anything; it only has to be a real id for CreateAutoScalingGroup to accept the template.
    ami = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    ec2.create_launch_template(
        LaunchTemplateName=template_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "autoscaling__cloudwatch"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=template_name))

    asg_name = ctx.unique_name("sim2real-xsvc-cwasg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": template_name, "Version": "$Latest"},
        MinSize=0, MaxSize=0, DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": "autoscaling__cloudwatch", "ResourceId": asg_name, "ResourceType": "auto-scaling-group"}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    policy_name = ctx.unique_name("sim2real-xsvc-cwasg-policy-")
    policy_arn = autoscaling.put_scaling_policy(
        AutoScalingGroupName=asg_name, PolicyName=policy_name,
        PolicyType="SimpleScaling", AdjustmentType="ChangeInCapacity", ScalingAdjustment=1,
    )["PolicyARN"]

    # ---- positive control: the group's own, well-formed policy ARN is accepted ------------------ #
    ok_name = ctx.unique_name("sim2real-xsvc-cwasg-alarm-ok-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ok_name]))
    cw.put_metric_alarm(
        AlarmName=ok_name, AlarmActions=[policy_arn],
        Tags=[{"Key": "sim2real", "Value": "autoscaling__cloudwatch"}], **_COMMON_ALARM_KWARGS,
    )
    stored = cw.describe_alarms(AlarmNames=[ok_name])["MetricAlarms"][0]
    assert stored["AlarmActions"] == [policy_arn], (
        f"the scalingPolicy ARN must round-trip verbatim through DescribeAlarms, got "
        f"{stored['AlarmActions']!r}"
    )

    # ---- negative: the relative id is missing its required policyName segment --------------------- #
    policy_id = policy_arn.split(":")[-3]
    truncated = (
        f"arn:aws:autoscaling:{ctx.region}:{ctx.account}:scalingPolicy:{policy_id}:"
        f"autoScalingGroupName/{asg_name}"
    )
    bad_name = ctx.unique_name("sim2real-xsvc-cwasg-alarm-bad-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[bad_name]))
    got = _reject(lambda: cw.put_metric_alarm(
        AlarmName=bad_name, AlarmActions=[truncated],
        Tags=[{"Key": "sim2real", "Value": "autoscaling__cloudwatch"}], **_COMMON_ALARM_KWARGS,
    ))
    want = (
        "ValidationError",
        f'The vendor "autoscaling" cannot be used with relative id scalingPolicy:{policy_id}:'
        f"autoScalingGroupName/{asg_name}. Allowed relative IDs must be in the format"
        "scalingPolicy:policy-id:autoScalingGroupName/group-friendly-name:policyName/policy-friendly-name",
    )
    assert got == want, f"expected {want!r} for a relative id missing its policyName segment, got {got!r}"
    left = cw.describe_alarms(AlarmNames=[bad_name])["MetricAlarms"]
    assert not left, f"a rejected PutMetricAlarm must leave no alarm behind, found {left!r}"

    # ---- negative: the same well-formed relative id naming a foreign region ----------------------- #
    foreign_region = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"
    foreign_action = policy_arn.replace(f":{ctx.region}:", f":{foreign_region}:", 1)
    region_name = ctx.unique_name("sim2real-xsvc-cwasg-alarm-region-")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[region_name]))
    got = _reject(lambda: cw.put_metric_alarm(
        AlarmName=region_name, AlarmActions=[foreign_action],
        Tags=[{"Key": "sim2real", "Value": "autoscaling__cloudwatch"}], **_COMMON_ALARM_KWARGS,
    ))
    want = ("ValidationError", f"Invalid region {foreign_region} specified. Only {ctx.region} is supported.")
    assert got == want, f"expected {want!r} for an action naming a foreign region, got {got!r}"
    left = cw.describe_alarms(AlarmNames=[region_name])["MetricAlarms"]
    assert not left, f"a rejected PutMetricAlarm must leave no alarm behind, found {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
