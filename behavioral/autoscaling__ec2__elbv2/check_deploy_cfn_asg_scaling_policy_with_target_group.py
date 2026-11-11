"""deploy-cfn-asg-scaling-policy-with-target-group."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-asg-scaling-policy-with-target-group"
GROUP = "deploy-behavior"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ImageId:
    Type: AWS::EC2::Image::Id
Resources:
  Vpc:
    Type: AWS::EC2::VPC
    Properties:
      CidrBlock: 10.40.0.0/16
      EnableDnsSupport: true
      EnableDnsHostnames: true
      Tags:
        - Key: sim2real:managed
          Value: "true"
  SubnetA:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.40.1.0/24
      AvailabilityZone: !Select [0, !GetAZs '']
      Tags:
        - Key: sim2real:managed
          Value: "true"
  SubnetB:
    Type: AWS::EC2::Subnet
    Properties:
      VpcId: !Ref Vpc
      CidrBlock: 10.40.2.0/24
      AvailabilityZone: !Select [1, !GetAZs '']
      Tags:
        - Key: sim2real:managed
          Value: "true"
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real-xsvc instance sg allowing HTTP for target health checks
      VpcId: !Ref Vpc
      SecurityGroupIngress:
        - IpProtocol: tcp
          FromPort: 80
          ToPort: 80
          CidrIp: 10.40.0.0/16
      Tags:
        - Key: sim2real:managed
          Value: "true"
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: !Ref ImageId
        InstanceType: t3.micro
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
        UserData:
          Fn::Base64: |
            #!/bin/bash
            cd /tmp
            nohup python3 -m http.server 80 >/tmp/http.log 2>&1 &
        TagSpecifications:
          - ResourceType: instance
            Tags:
              - Key: sim2real:managed
                Value: "true"
  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: !Ref Vpc
      Port: 80
      Protocol: HTTP
      TargetType: instance
      HealthCheckIntervalSeconds: 10
      HealthCheckTimeoutSeconds: 5
      HealthyThresholdCount: 2
      UnhealthyThresholdCount: 2
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Type: application
      Scheme: internal
      Subnets:
        - !Ref SubnetA
        - !Ref SubnetB
      SecurityGroups:
        - !Ref InstanceSecurityGroup
      Tags:
        - Key: sim2real:managed
          Value: "true"
  Listener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Port: 80
      Protocol: HTTP
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref TargetGroup
  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    DependsOn: Listener
    Properties:
      MinSize: "1"
      MaxSize: "3"
      DesiredCapacity: "1"
      VPCZoneIdentifier:
        - !Ref SubnetA
        - !Ref SubnetB
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      TargetGroupARNs:
        - !Ref TargetGroup
      Tags:
        - Key: sim2real:managed
          Value: "true"
          PropagateAtLaunch: true
  ScaleOutPolicy:
    Type: AWS::AutoScaling::ScalingPolicy
    Properties:
      AutoScalingGroupName: !Ref AutoScalingGroup
      PolicyType: SimpleScaling
      AdjustmentType: ChangeInCapacity
      ScalingAdjustment: 1
      Cooldown: "0"
Outputs:
  TargetGroupArn:
    Value: !Ref TargetGroup
  AutoScalingGroupName:
    Value: !Ref AutoScalingGroup
  ScalingPolicyArn:
    Value: !Ref ScaleOutPolicy
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Executing a target-tracking-style scale-out policy on a CFN-deployed ASG launches a NEW
    EC2 instance that itself registers (and becomes healthy) in the wired target group."""
    ami_id = _get_al2_ami(ctx)

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"ImageId": ami_id},
        capabilities=[],
        timeout_s=400,
    )
    tg_arn = result["outputs"]["TargetGroupArn"]
    asg_name = result["outputs"]["AutoScalingGroupName"]
    policy_arn = result["outputs"]["ScalingPolicyArn"]

    autoscaling = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    def _in_service_ids():
        groups = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]
        instances = groups[0]["Instances"] if groups else []
        return [
            i["InstanceId"] for i in instances if i["LifecycleState"] == "InService"
        ]

    baseline_ids = _poll_until(
        _in_service_ids,
        lambda ids: len(ids) >= 1,
        timeout_s=400,
        interval_s=10,
        description="baseline ASG instance reaches InService",
    )
    assert len(baseline_ids) == 1, (
        f"expected exactly 1 baseline InService instance, got {baseline_ids!r}"
    )

    # Deterministically force the scale-out defined by the policy rather than waiting on a real
    # CloudWatch metric breach.
    autoscaling.execute_policy(PolicyName=policy_arn, HonorCooldown=False)

    scaled_ids = _poll_until(
        _in_service_ids,
        lambda ids: len(ids) >= 2,
        timeout_s=400,
        interval_s=10,
        description="ASG scales out to 2 InService instances",
    )
    new_instance_ids = set(scaled_ids) - set(baseline_ids)
    assert len(new_instance_ids) >= 1, "scale-out did not launch a new instance"

    def _healthy_target_ids():
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return [
            t["Target"]["Id"] for t in health if t["TargetHealth"]["State"] == "healthy"
        ]

    healthy = _poll_until(
        _healthy_target_ids,
        lambda ids: new_instance_ids.issubset(set(ids)),
        timeout_s=300,
        interval_s=10,
        description="newly scaled-out instance becomes a healthy target",
    )
    assert new_instance_ids.issubset(set(healthy)), (
        f"expected new instances {new_instance_ids!r} to be healthy targets, healthy={healthy!r}"
    )


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
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=540,
        interval_s=10.0,
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
    template_body = template.read_text() if isinstance(template, Path) else template
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
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
