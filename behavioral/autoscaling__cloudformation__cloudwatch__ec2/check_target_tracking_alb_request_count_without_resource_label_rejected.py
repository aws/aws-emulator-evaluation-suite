"""target-tracking-alb-request-count-without-resource-label-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "target-tracking-alb-request-count-without-resource-label-rejected"
GROUP = "target-tracking-policy-rejected"
SERVICES = ["autoscaling", "cloudformation", "cloudwatch", "ec2"]

_AMI_PARAM = "resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.1-x86_64"
_INSTANCE_TYPE = "t3.micro"
_EXPECTED_CODE = "ValidationError"
_EXPECTED_MESSAGE = (
    "Resource label should be specified for predefined metric type ALBRequestCountPerTarget"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:metrics", "plane:control")
def run(ctx) -> None:
    """A target-tracking policy on ALBRequestCountPerTarget with no ResourceLabel is refused, and
    leaves no policy or CloudWatch alarm; an identical CPU policy on the group is accepted with alarms.
    """
    ctx.verify_account_safety()
    asg = ctx.client("autoscaling")
    cw = ctx.client("cloudwatch")
    ec2 = ctx.client("ec2")
    tag_spec = [{"Key": "sim2real", "Value": CHECK}]

    # ---- estate: own VPC + subnet in an AZ that offers the type, an LT, a zero-capacity ASG ----
    offered = {o["Location"] for page in ec2.get_paginator(
        "describe_instance_type_offerings").paginate(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [_INSTANCE_TYPE]}])
        for o in page["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {_INSTANCE_TYPE!r}; offered={sorted(offered)!r}"

    vpc_id = ec2.create_vpc(CidrBlock="10.83.0.0/16", TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag_spec}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.83.1.0/24", AvailabilityZone=usable[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    lt_name = ctx.unique_name("sim2real-xsvc-ttlt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _AMI_PARAM, "InstanceType": _INSTANCE_TYPE},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": tag_spec}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    group = ctx.unique_name("sim2real-xsvc-ttasg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group, MinSize=0, MaxSize=1, DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _delete_group(asg, group))

    # ---- positive control: CPU target tracking on the same group is accepted -----------------
    good = ctx.unique_name("sim2real-tt-cpu-")
    asg.put_scaling_policy(
        AutoScalingGroupName=group, PolicyName=good, PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={
            "PredefinedMetricSpecification": {"PredefinedMetricType": "ASGAverageCPUUtilization"},
            "TargetValue": 50.0})
    ctx.on_cleanup(lambda: _delete_policy(asg, group, good))
    accepted = asg.describe_policies(AutoScalingGroupName=group)["ScalingPolicies"]
    assert [p["PolicyName"] for p in accepted] == [good], (
        f"after the control policy, group {group!r} has policies "
        f"{[p['PolicyName'] for p in accepted]!r}, expected exactly [{good!r}]")
    control_alarms = sorted(a["AlarmName"] for a in accepted[0].get("Alarms", []))
    assert len(control_alarms) == 2, (
        f"the accepted CPU target-tracking policy lists alarms {control_alarms!r}, expected two")
    held = sorted(a["AlarmName"] for a in cw.describe_alarms(
        AlarmNames=control_alarms)["MetricAlarms"])
    assert held == control_alarms, (
        f"CloudWatch holds {held!r} of the control policy's alarms {control_alarms!r}")
    before = _group_alarms(cw, group)
    assert before == control_alarms, (
        f"alarms scoped to {group!r} are {before!r}; only the control's {control_alarms!r} exist")

    # ---- ALBRequestCountPerTarget with no ResourceLabel ----------------------------------------
    # The model marks ResourceLabel optional; requiring it for this metric is a service rule.
    bad = ctx.unique_name("sim2real-tt-alb-")
    code, message = _error(lambda: asg.put_scaling_policy(
        AutoScalingGroupName=group, PolicyName=bad, PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={
            "PredefinedMetricSpecification": {"PredefinedMetricType": "ALBRequestCountPerTarget"},
            "TargetValue": 100.0}),
        on_success=lambda: ctx.on_cleanup(lambda: _delete_policy(asg, group, bad)))
    assert code == _EXPECTED_CODE, (
        f"PutScalingPolicy(ALBRequestCountPerTarget, no ResourceLabel) raised {code!r}, "
        f"expected {_EXPECTED_CODE!r}")
    assert message == _EXPECTED_MESSAGE, (
        f"PutScalingPolicy(ALBRequestCountPerTarget, no ResourceLabel) said {message!r}, "
        f"expected {_EXPECTED_MESSAGE!r}")

    # ---- effect absent: no such policy, no new alarm, control untouched -----------------------
    after = asg.describe_policies(AutoScalingGroupName=group)["ScalingPolicies"]
    assert [p["PolicyName"] for p in after] == [good], (
        f"after the refused call group {group!r} has policies "
        f"{[p['PolicyName'] for p in after]!r}; the refused policy must not exist")
    named = asg.describe_policies(AutoScalingGroupName=group, PolicyNames=[bad])["ScalingPolicies"]
    assert named == [], f"DescribePolicies(PolicyNames=[{bad!r}]) returned {named!r}"
    assert _group_alarms(cw, group) == control_alarms, (
        f"alarms scoped to {group!r} changed to {_group_alarms(cw, group)!r} after a refused "
        f"policy; expected only the control's {control_alarms!r}")


def _error(fn, on_success=None) -> tuple[str, str]:
    """The AWS error ``(code, message)`` a call raises. On an unexpected SUCCESS, register the
    teardown for what was just created and then raise, so the success is reported and never leaks."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return str(err["Code"]), str(err.get("Message", ""))
    if on_success is not None:
        on_success()
    raise AssertionError("call succeeded but was expected to be refused")


def _group_alarms(cw, group: str) -> list[str]:
    """Every target-tracking alarm Auto Scaling created for this group (its names start
    TargetTracking-<group>-), paginated; the prefix only this check's group can occupy."""
    return sorted(a["AlarmName"] for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNamePrefix=f"TargetTracking-{group}-") for a in page["MetricAlarms"])


def _delete_policy(asg, group: str, name: str) -> None:
    try:
        asg.delete_policy(AutoScalingGroupName=group, PolicyName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise


def _delete_group(asg, group: str) -> None:
    """Force-delete the zero-capacity group and poll until it is gone (it launched nothing)."""
    asg.delete_auto_scaling_group(AutoScalingGroupName=group, ForceDelete=True)
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if not asg.describe_auto_scaling_groups(
                AutoScalingGroupNames=[group])["AutoScalingGroups"]:
            return
        time.sleep(3)
    raise RuntimeError(f"auto scaling group {group} still listed 45s after ForceDelete")


def _retry_dependency(fn, attempts: int = 6) -> None:
    for _ in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DependencyViolation":
                raise
            time.sleep(3)
    fn()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
