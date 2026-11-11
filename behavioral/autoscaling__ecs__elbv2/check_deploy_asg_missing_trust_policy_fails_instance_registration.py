"""deploy-asg-missing-trust-policy-fails-instance-registration."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-asg-missing-trust-policy-fails-instance-registration"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_TEMPLATE_GOOD = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real asg permission-boundary sg (good)
      VpcId: __VPC_ID__
  GoodRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
  GoodInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref GoodRole
  LaunchTemplateGood:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}'
        InstanceType: t3.micro
        IamInstanceProfile:
          Arn: !GetAtt GoodInstanceProfile.Arn
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
  TargetGroupGood:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: __VPC_ID__
      Port: 80
      Protocol: HTTP
      TargetType: instance
  AutoScalingGroupGood:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: __ASG_GOOD_NAME__
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplateGood
        Version: !GetAtt LaunchTemplateGood.LatestVersionNumber
      MinSize: '1'
      MaxSize: '1'
      DesiredCapacity: '1'
      VPCZoneIdentifier: [__SUBNET_A__, __SUBNET_B__]
      TargetGroupARNs:
        - !Ref TargetGroupGood
Outputs:
  TargetGroupGoodArn:
    Value: !Ref TargetGroupGood
"""

_TEMPLATE_BROKEN = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real asg permission-boundary sg (broken)
      VpcId: __VPC_ID__
  LaunchTemplateBroken:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}'
        InstanceType: t3.micro
        IamInstanceProfile:
          Name: __BROKEN_PROFILE_NAME__
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
  TargetGroupBroken:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: __VPC_ID__
      Port: 80
      Protocol: HTTP
      TargetType: instance
  AutoScalingGroupBroken:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: __ASG_BROKEN_NAME__
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplateBroken
        Version: !GetAtt LaunchTemplateBroken.LatestVersionNumber
      MinSize: '1'
      MaxSize: '1'
      DesiredCapacity: '1'
      VPCZoneIdentifier: [__SUBNET_A__, __SUBNET_B__]
      TargetGroupARNs:
        - !Ref TargetGroupBroken
Outputs:
  TargetGroupBrokenArn:
    Value: !Ref TargetGroupBroken
"""


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A launch template naming a nonexistent instance profile makes CreateAutoScalingGroup fail, so
    the stack never launches or registers an instance; a correctly wired sibling stack registers
    one."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    asg_good_name = _xname(ctx, "asggood")
    asg_broken_name = _xname(ctx, "asgbroken")
    broken_profile_name = _xname(ctx, "nonexistent-profile")

    good_template = (
        _TEMPLATE_GOOD.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
        .replace("__ASG_GOOD_NAME__", asg_good_name)
    )
    broken_template = (
        _TEMPLATE_BROKEN.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
        .replace("__ASG_BROKEN_NAME__", asg_broken_name)
        .replace("__BROKEN_PROFILE_NAME__", broken_profile_name)
    )

    autoscaling = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    # (c) positive control: a correctly-configured ASG deploys, launches, and registers.
    good_result = _deploy_cfn(ctx, good_template, timeout_s=300)
    tg_good_arn = good_result["outputs"]["TargetGroupGoodArn"]

    def _good_in_service():
        group = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_good_name]
        )["AutoScalingGroups"][0]
        return [
            i["InstanceId"]
            for i in group["Instances"]
            if i["LifecycleState"] == "InService"
        ]

    good_instances = _poll_until(
        _good_in_service,
        lambda ids: len(ids) >= 1,
        timeout_s=240,
        interval_s=10.0,
        description="good ASG instance reaches InService",
    )
    good_targets = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_good_arn)[
            "TargetHealthDescriptions"
        ],
        lambda targets: len(targets) >= 1,
        timeout_s=120,
        interval_s=5.0,
        description="good target group registers a target",
    )
    good_target_ids = {t["Target"]["Id"] for t in good_targets}
    assert good_target_ids == set(good_instances), (
        f"expected registered target ids {sorted(good_target_ids)} to equal the good ASG's "
        f"instance ids {sorted(good_instances)}"
    )

    # (a)+(b) the specific failure: the broken stack's own creation fails synchronously
    # (CreateAutoScalingGroup rejects the unresolved instance profile), so it never produces
    # an ASG, an instance, or a registered target.
    broken_status = _deploy_cfn_expect_failure(ctx, broken_template, timeout_s=300)
    assert broken_status["status"] in {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
    }, f"broken stack unexpectedly succeeded: {broken_status}"
    assert any(
        "instance profile" in f.lower() for f in broken_status["failed_resources"]
    ), (
        f"no failed resource mentions the instance profile: {broken_status['failed_resources']}"
    )

    groups = autoscaling.describe_auto_scaling_groups(
        AutoScalingGroupNames=[asg_broken_name]
    )["AutoScalingGroups"]
    assert groups == [], f"broken ASG unexpectedly exists: {groups}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'
        if status == "DELETE_FAILED":
            cfn.delete_stack(StackName=stack_name)
        return status

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=1500,
        interval_s=15.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        events = cfn.describe_stack_events(StackName=name)["StackEvents"]
        failed = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
            for e in events
            if e["ResourceStatus"].endswith("FAILED")
        ]
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; failed resources: {failed}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _default_vpc_and_subnets(ctx, min_subnets: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region — this check discovers a shared network VPC "
            "and subnets via EC2 rather than building custom networking; provisioning a VPC "
            "just for this check would close the gap."
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    )["Subnets"]
    if len(subnets) < min_subnets:
        raise AssertionError(
            f"shared network VPC has fewer than {min_subnets} shared-network subnet"
        )
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())[:min_subnets]
    return vpc_id, ids


def _deploy_cfn_expect_failure(
    ctx, template, *, stack_name=None, timeout_s=300.0
) -> dict[str, Any]:
    """Deploy a stack that is EXPECTED to fail to create; return its terminal status and the
    failure reasons instead of raising. Cleanup (delete_stack) is still registered so the
    (rolled-back) stack shell is removed afterward."""
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    stack_id = cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name} to reach a terminal status",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    events = cfn.describe_stack_events(StackName=name)["StackEvents"]
    failed = [
        f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]
    return {
        "stack_name": name,
        "stack_id": stack_id,
        "status": stack["StackStatus"],
        "failed_resources": failed,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
