"""target-tracking-policy-creates-alarms."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "target-tracking-policy-creates-alarms"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']

#: Public SSM parameter for the latest AL2023 x86_64 AMI.
_CATALOG_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _catalog_ami(ctx) -> str:
    """The AMI id from the public AL2023 SSM parameter."""
    from botocore.exceptions import ClientError

    try:
        return ctx.client("ssm").get_parameter(Name=_CATALOG_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        raise AssertionError(
            f"prerequisite catalog-ami: GetParameter({_CATALOG_AMI_PARAM}) failed: {exc}"
        ) from exc
#: Bounded convergence for the policy's alarms to leave CloudWatch, sized from the default budget.
_CONVERGE_WAIT_S = 240


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A TargetTrackingScaling policy's alarms exist in CloudWatch with the right metric, thresholds
    and action; manual ExecutePolicy on it is refused. Deleting it removes the policy and both
    alarms, and the dead policy cannot be executed."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(
                "no default-for-az subnet (the account baseline) for Auto Scaling group placement"
            )
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _catalog_ami(ctx), "InstanceType": instance_type},
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _error_response(fn):
        try:
            result = fn()
        except ClientError as exc:
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return dict(exc.response.get("Error", {}), HTTPStatusCode=status)
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

    def _desired_capacity(asg_name):
        return as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]["DesiredCapacity"]

    name = _make_asg(min_size=0, max_size=4, desired_capacity=0)
    policy_name = ctx.unique_name("sim2real-behav-as-tt-")
    target_value = 55.0

    # Positive control: ExecutePolicy generically works against this exact ASG (credentials,
    # state, permissions are all fine), via a net-zero SimpleScaling policy so it never actually
    # moves capacity. Without this, the later ValidationError could mean "every ExecutePolicy call
    # is rejected here" rather than "TargetTrackingScaling specifically forbids manual execution".
    control_name = ctx.unique_name("sim2real-behav-as-ctl-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=control_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=0,
        Cooldown=0,
    )
    ctx.on_cleanup(lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=control_name))
    as_.execute_policy(AutoScalingGroupName=name, PolicyName=control_name)

    resp = as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="TargetTrackingScaling",
        TargetTrackingConfiguration={
            "PredefinedMetricSpecification": {
                "PredefinedMetricType": "ASGAverageCPUUtilization"
            },
            "TargetValue": target_value,
        },
    )
    def _delete_policy_if_present():
        # The check deletes the policy itself; teardown only covers a run that stops before that.
        if as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])["ScalingPolicies"]:
            as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name)

    ctx.on_cleanup(_delete_policy_if_present)
    policy_arn = resp["PolicyARN"]
    arn_re = (
        rf"arn:aws:autoscaling:{re.escape(ctx.region)}:{re.escape(ctx.account)}:scalingPolicy:"
        rf"[0-9a-f-]+:autoScalingGroupName/{re.escape(name)}:policyName/{re.escape(policy_name)}"
    )
    assert re.fullmatch(arn_re, policy_arn), f"expected PolicyARN matching {arn_re!r}, got {policy_arn!r}"
    alarm_names = sorted(a["AlarmName"] for a in resp.get("Alarms", []))
    assert len(alarm_names) == 2, (
        f"a predefined-metric target-tracking policy must materialise exactly two CloudWatch "
        f"alarms (scale-out and scale-in), got {resp.get('Alarms')}"
    )

    policy = as_.describe_policies(
        AutoScalingGroupName=name, PolicyNames=[policy_name]
    )["ScalingPolicies"][0]
    assert policy["PolicyType"] == "TargetTrackingScaling", policy
    assert policy["TargetTrackingConfiguration"]["TargetValue"] == target_value, policy
    assert policy["TargetTrackingConfiguration"].get("DisableScaleIn") is False, policy
    assert sorted(a["AlarmName"] for a in policy["Alarms"]) == alarm_names, (
        f"describe_policies reports different alarms than put_scaling_policy minted: "
        f"{policy['Alarms']!r} vs {resp['Alarms']!r}"
    )

    # The destination for "creates alarms" is CloudWatch, not autoscaling's own bookkeeping --
    # PutScalingPolicy and DescribePolicies both merely echo the alarm refs they were handed.
    # For a CPUUtilization predefined metric, AWS creates exactly one
    # "AlarmHigh" (scale-out, GreaterThanThreshold at TargetValue, 3 x 60s periods) and one
    # "AlarmLow" (scale-in, LessThanThreshold at 90% of TargetValue, 15 x 60s periods) alarm,
    # each pointing its sole alarm action back at the policy ARN.
    cw = ctx.client("cloudwatch")
    alarms = {a["AlarmName"]: a for a in cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]}
    assert sorted(alarms) == alarm_names, (
        f"CloudWatch only knows about {sorted(alarms)!r} of the alarms autoscaling claimed to "
        f"have created: {alarm_names!r}"
    )
    high = next(n for n in alarm_names if "-AlarmHigh-" in n)
    low = next(n for n in alarm_names if "-AlarmLow-" in n)
    expected = {
        high: {"ComparisonOperator": "GreaterThanThreshold", "Threshold": target_value,
               "EvaluationPeriods": 3},
        low: {"ComparisonOperator": "LessThanThreshold", "Threshold": target_value * 0.9,
              "EvaluationPeriods": 15},
    }
    for alarm_name, want in expected.items():
        alarm = alarms[alarm_name]
        assert alarm["Namespace"] == "AWS/EC2", alarm
        assert alarm["MetricName"] == "CPUUtilization", alarm
        assert alarm["Dimensions"] == [{"Name": "AutoScalingGroupName", "Value": name}], alarm
        assert alarm["Statistic"] == "Average", alarm
        assert alarm["Period"] == 60, alarm
        for field, value in want.items():
            assert alarm[field] == value, (
                f"{alarm_name} has {field}={alarm[field]!r}, expected {value!r} "
                f"(target value {target_value})"
            )
        assert alarm["AlarmActions"] == [policy_arn], (
            f"{alarm_name} lists alarm actions {alarm['AlarmActions']!r}; exactly the scaling "
            f"policy {policy_arn!r} must be wired up, or a breach reaches nothing or too much"
        )

    before = _desired_capacity(name)

    error = _error_response(
        lambda: as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name)
    )
    assert error.get("Code") == "ValidationError", (
        f"ExecutePolicy on a target-tracking policy must be rejected, got {error.get('Code')!r}"
    )
    assert error.get("HTTPStatusCode") == 400, (
        f"expected HTTP 400 for the refused ExecutePolicy, got {error.get('HTTPStatusCode')!r}"
    )
    expected_message = "ExecutePolicy is not allowed for policy type TargetTrackingScaling"
    assert error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {error.get("Message")!r}'

    after = _desired_capacity(name)
    assert after == before, (
        f"the rejected ExecutePolicy call changed DesiredCapacity from {before} to {after}"
    )
    activities = as_.describe_scaling_activities(AutoScalingGroupName=name)["Activities"]
    assert not any(policy_name in (a.get("Cause") or "") for a in activities), (
        f"the rejected ExecutePolicy call left a scaling activity behind: {activities!r}"
    )

    as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name)
    # Beat 1: the by-name policy read reports the miss in-band.
    remaining = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy_name])["ScalingPolicies"]
    assert remaining == [], f"deleted policy still described: {remaining!r}"
    # Beat 2: both of the policy's alarms leave CloudWatch (bounded convergence).
    deadline = time.monotonic() + _CONVERGE_WAIT_S
    while True:
        left = [a["AlarmName"] for a in cw.describe_alarms(AlarmNames=alarm_names)["MetricAlarms"]]
        if not left:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"the deleted policy's alarms are still in CloudWatch: {left!r}")
        time.sleep(3)
    # Beat 3: executing the dead policy is refused.
    dead = _error_response(lambda: as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name))
    assert dead.get("Code") == "ValidationError", (
        f"ExecutePolicy on the deleted policy must be ValidationError, got {dead.get('Code')!r}"
    )
    assert dead.get("HTTPStatusCode") == 400, (
        f"expected HTTP 400 executing the deleted policy, got {dead.get('HTTPStatusCode')!r}"
    )
    # AWS names the policy: "Policy <name> not found".
    expected_message = f"Policy {policy_name} not found"
    assert dead.get("Message") == expected_message, f'expected the message {expected_message!r}, got {dead.get("Message")!r}'


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
