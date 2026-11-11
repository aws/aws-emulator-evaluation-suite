"""deploy-cfn-stack-asg-elb-ec2-integration."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-asg-elb-ec2-integration"
GROUP = "deploy-behavior"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  VpcId:
    Type: AWS::EC2::VPC::Id
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  ImageId:
    Type: AWS::EC2::Image::Id
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real-xsvc instance sg allowing HTTP for target health checks
      VpcId: !Ref VpcId
      Tags:
        - Key: sim2real:managed
          Value: "true"
  InstanceSecurityGroupSelfIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref InstanceSecurityGroup
      IpProtocol: tcp
      FromPort: 80
      ToPort: 80
      SourceSecurityGroupId: !Ref InstanceSecurityGroup
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
      VpcId: !Ref VpcId
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
      Subnets: !Ref SubnetIds
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
      MaxSize: "1"
      DesiredCapacity: "1"
      VPCZoneIdentifier: !Ref SubnetIds
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      TargetGroupARNs:
        - !Ref TargetGroup
      Tags:
        - Key: sim2real:managed
          Value: "true"
          PropagateAtLaunch: true
Outputs:
  TargetGroupArn:
    Value: !Ref TargetGroup
  AutoScalingGroupName:
    Value: !Ref AutoScalingGroup
"""


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN stack with a launch-template ASG wired to a target group ends with the launched
    EC2 instances actually registered (and eventually healthy) in that target group."""
    vpc_id, subnet_ids = _get_default_network(ctx)
    ami_id = _get_al2_ami(ctx)

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={
            "VpcId": vpc_id,
            "SubnetIds": ",".join(subnet_ids),
            "ImageId": ami_id,
        },
        capabilities=[],
        timeout_s=400,
    )
    tg_arn = result["outputs"]["TargetGroupArn"]
    asg_name = result["outputs"]["AutoScalingGroupName"]

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

    instance_ids = _poll_until(
        _in_service_ids,
        lambda ids: len(ids) >= 1,
        timeout_s=400,
        interval_s=10,
        description="ASG instance reaches InService",
    )

    def _registered_target_ids():
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return [t["Target"]["Id"] for t in health]

    registered = _poll_until(
        _registered_target_ids,
        lambda ids: set(instance_ids).issubset(set(ids)),
        timeout_s=180,
        interval_s=10,
        description="EC2 instances register with the target group",
    )
    assert set(registered) == set(instance_ids), (
        f"target group should register exactly the ASG's instance(s) {instance_ids}, "
        f"got {registered}"
    )

    def _healthy_target_ids():
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return [
            t["Target"]["Id"] for t in health if t["TargetHealth"]["State"] == "healthy"
        ]

    healthy = _poll_until(
        _healthy_target_ids,
        lambda ids: set(instance_ids).issubset(set(ids)),
        timeout_s=300,
        interval_s=10,
        description="registered EC2 instances become healthy targets",
    )
    assert set(healthy) == set(instance_ids), (
        f"target group should report exactly the ASG's instance(s) {instance_ids} as healthy, "
        f"got {healthy}"
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
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"
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


def _get_default_network(ctx) -> tuple[str, list[str]]:

    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to launch test EC2 instances"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    if len(subnets) < 2:
        raise AssertionError("shared network has fewer than 2 subnets available")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    return vpc_id, subnet_ids


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
