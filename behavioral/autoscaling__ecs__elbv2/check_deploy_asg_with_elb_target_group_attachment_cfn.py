"""deploy-asg-with-elb-target-group-attachment-cfn."""
from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-asg-with-elb-target-group-attachment-cfn"
GROUP = "deploy-behavior"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real asg instance sg
      VpcId: __VPC_ID__
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}'
        InstanceType: t3.micro
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
  TargetGroup:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: __VPC_ID__
      Port: 80
      Protocol: HTTP
      TargetType: instance
  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      MinSize: '1'
      MaxSize: '1'
      DesiredCapacity: '1'
      VPCZoneIdentifier: [__SUBNET_A__, __SUBNET_B__]
      TargetGroupARNs:
        - !Ref TargetGroup
      Tags:
        - Key: Name
          Value: sim2real-xsvc-asg-instance
          PropagateAtLaunch: true
Outputs:
  AutoScalingGroupOut:
    Value: !Ref AutoScalingGroup
  TargetGroupArn:
    Value: !Ref TargetGroup
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed ASG with TargetGroupARNs registers its launched EC2 instances as elbv2
    targets — the ASG service itself (not the caller) must drive RegisterTargets as instances
    become InService, and the registered target IDs must exactly match the ASG's instances."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    template = (
        _TEMPLATE.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
    )
    result = _deploy_cfn(ctx, template, timeout_s=300)
    asg_name = result["outputs"]["AutoScalingGroupOut"]
    tg_arn = result["outputs"]["TargetGroupArn"]

    autoscaling = ctx.client("autoscaling")
    elbv2 = ctx.client("elbv2")

    def _in_service_instances():
        group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
            "AutoScalingGroups"
        ][0]
        return [i["InstanceId"] for i in group["Instances"] if i["LifecycleState"] == "InService"]

    instance_ids = _poll_until(
        _in_service_instances,
        lambda ids: len(ids) >= 1,
        timeout_s=240,
        interval_s=10.0,
        description="ASG instance reaches InService",
    )

    def _registered_target_ids():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return {t["Target"]["Id"] for t in resp["TargetHealthDescriptions"]}

    registered = _poll_until(
        _registered_target_ids,
        lambda ids: len(ids) >= 1,
        timeout_s=120,
        interval_s=5.0,
        description="target group has a registered target",
    )
    assert registered == set(instance_ids), (
        f"registered targets {registered} do not match ASG instances {instance_ids}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _default_vpc_and_subnets(ctx, min_subnets: int = 2) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region — this check discovers a shared network VPC "
            "and subnets via EC2 rather than building custom networking; provisioning a VPC "
            "just for this check would close the gap."
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if len(subnets) < min_subnets:
        raise AssertionError(f"shared network has fewer than {min_subnets} shared-network subnet")
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    ids = list(by_az.values())[:min_subnets]
    return vpc_id, ids


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
