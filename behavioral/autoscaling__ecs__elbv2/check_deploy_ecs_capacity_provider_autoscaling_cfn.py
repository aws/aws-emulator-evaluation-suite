"""deploy-ecs-capacity-provider-autoscaling-cfn."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-capacity-provider-autoscaling-cfn"
GROUP = "deploy-behavior"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real ecs capacity provider instance sg
      VpcId: __VPC_ID__
  InstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role
  InstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref InstanceRole
  LaunchTemplate:
    Type: AWS::EC2::LaunchTemplate
    Properties:
      LaunchTemplateData:
        ImageId: '{{resolve:ssm:/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id}}'
        InstanceType: t3.micro
        IamInstanceProfile:
          Arn: !GetAtt InstanceProfile.Arn
        SecurityGroupIds:
          - !Ref InstanceSecurityGroup
        UserData:
          Fn::Base64: |
            #!/bin/bash
            echo ECS_CLUSTER=__CLUSTER_NAME__ >> /etc/ecs/ecs.config
  AutoScalingGroup:
    Type: AWS::AutoScaling::AutoScalingGroup
    Properties:
      AutoScalingGroupName: __ASG_NAME__
      LaunchTemplate:
        LaunchTemplateId: !Ref LaunchTemplate
        Version: !GetAtt LaunchTemplate.LatestVersionNumber
      MinSize: '0'
      MaxSize: '3'
      DesiredCapacity: '0'
      VPCZoneIdentifier: [__SUBNET_A__, __SUBNET_B__]
      Tags:
        - Key: Name
          Value: sim2real-xsvc-cp-instance
          PropagateAtLaunch: true
  CapacityProvider:
    Type: AWS::ECS::CapacityProvider
    DependsOn: AutoScalingGroup
    Properties:
      Name: __CP_NAME__
      AutoScalingGroupProvider:
        AutoScalingGroupArn: __ASG_NAME__
        ManagedScaling:
          Status: ENABLED
          TargetCapacity: 100
          MinimumScalingStepSize: 1
          MaximumScalingStepSize: 1
          InstanceWarmupPeriod: 60
  Cluster:
    Type: AWS::ECS::Cluster
    DependsOn: CapacityProvider
    Properties:
      ClusterName: __CLUSTER_NAME__
      CapacityProviders:
        - !Ref CapacityProvider
      DefaultCapacityProviderStrategy:
        - CapacityProvider: !Ref CapacityProvider
          Weight: 1
          Base: 0
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [EC2]
      NetworkMode: bridge
      ContainerDefinitions:
        - Name: app
          Image: public.ecr.aws/docker/library/httpd:2.4
          Cpu: 128
          Memory: 128
          PortMappings:
            - ContainerPort: 80
              HostPort: 0
              Protocol: tcp
  Service:
    Type: AWS::ECS::Service
    DependsOn: Cluster
    Properties:
      Cluster: __CLUSTER_NAME__
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 1
      CapacityProviderStrategy:
        - CapacityProvider: !Ref CapacityProvider
          Weight: 1
          Base: 0
"""


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:deploy",
    "concern:e2e",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN-deployed ECS capacity provider bound to a 0-capacity ASG makes ECS cluster auto
    scaling scale the ASG out once a task needs placement, and a container instance registers."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx)
    cluster_name = _xname(ctx, "cpcluster")
    asg_name = _xname(ctx, "cpasg")
    cp_name = _xname(ctx, "capprov")
    template = (
        _TEMPLATE.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
        .replace("__CLUSTER_NAME__", cluster_name)
        .replace("__ASG_NAME__", asg_name)
        .replace("__CP_NAME__", cp_name)
    )
    # AWS::ECS::Service makes CloudFormation wait for service steady state before CREATE_COMPLETE,
    # which with a 0-capacity ASG needs the alarm-driven scale-out first: most of the wait is here.
    _deploy_cfn(ctx, template, timeout_s=1300)

    autoscaling = ctx.client("autoscaling")
    ecs = ctx.client("ecs")

    def _state():
        group = autoscaling.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"][0]
        instances = ecs.list_container_instances(cluster=cluster_name).get(
            "containerInstanceArns", []
        )
        return {
            "desired_capacity": group["DesiredCapacity"],
            "container_instances": len(instances),
        }

    state = _poll_until(
        _state,
        lambda s: s["desired_capacity"] > 0 and s["container_instances"] >= 1,
        timeout_s=400,
        interval_s=15.0,
        description="ECS capacity provider scales the ASG out and registers a container instance",
    )
    assert state["desired_capacity"] > 0, (
        f"expected the ECS capacity provider to scale the ASG {asg_name} out from 0, got "
        f"desired_capacity={state['desired_capacity']}"
    )
    assert state["container_instances"] >= 1, (
        f"expected at least one container instance registered with cluster {cluster_name}, got "
        f"container_instances={state['container_instances']}"
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
    # The cluster cannot be deleted while the ASG's instances are still registered with it, so
    # scale the ASG to zero before (and again on every retry of) the stack delete.
    def _scale_in_asgs():
        try:
            resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return
        for res in resources:
            if res["ResourceType"] == "AWS::AutoScaling::AutoScalingGroup" and res.get("PhysicalResourceId"):
                try:
                    ctx.client("autoscaling").update_auto_scaling_group(
                        AutoScalingGroupName=res["PhysicalResourceId"], MinSize=0, DesiredCapacity=0
                    )
                except ClientError as exc:
                    err = exc.response["Error"]
                    # A scaling activity in flight refuses the scale-in; the stack delete still removes the group.
                    if err["Code"] in ("ScalingActivityInProgress", "ResourceContention"):
                        continue
                    if err["Code"] != "ValidationError" or "not found" not in err.get("Message", ""):
                        raise

    _scale_in_asgs()
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
            _scale_in_asgs()
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
    _record_stack_id = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(_record_stack_id)
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


def _task_definition_teardown(ctx, stack_name: str):
    """Register the deletion of every ECS task definition revision the stack (and its nested
    stacks) registers, run once the stack is deleted: CloudFormation only deregisters them,
    which leaves INACTIVE revisions. Returns the cleanup that records the stack id; register it
    after the stack's own deletion so it runs before it."""
    state: dict = {}
    ctx.on_cleanup(lambda: _delete_stack_task_definitions(ctx, state.get("stack_id")))

    def _record_stack_id() -> None:
        try:
            state["stack_id"] = ctx.client("cloudformation").describe_stacks(
                StackName=stack_name)["Stacks"][0]["StackId"]
        except ClientError as exc:
            if "does not exist" not in exc.response["Error"].get("Message", ""):
                raise

    return _record_stack_id


def _delete_stack_task_definitions(ctx, stack_id) -> None:
    """Wait for the stack's deletion, then delete each task definition revision it registered."""
    if stack_id is None:
        return
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )
    arns, pending, seen = set(), [stack_id], set()
    while pending:
        sid = pending.pop()
        if sid in seen:
            continue
        seen.add(sid)
        for page in cfn.get_paginator("describe_stack_events").paginate(StackName=sid):
            for event in page["StackEvents"]:
                physical = event.get("PhysicalResourceId") or ""
                if not physical.startswith("arn:") or event["ResourceStatus"] not in (
                        "CREATE_COMPLETE", "UPDATE_COMPLETE"):
                    continue
                if event["ResourceType"] == "AWS::ECS::TaskDefinition":
                    arns.add(physical)
                elif event["ResourceType"] == "AWS::CloudFormation::Stack" and physical != sid:
                    pending.append(physical)
    for arn in sorted(arns):
        try:
            status = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]["status"]
        except ClientError as exc:
            if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
                continue
            raise
        if status == "DELETE_IN_PROGRESS":
            continue
        if status == "ACTIVE":
            ecs.deregister_task_definition(taskDefinition=arn)
        failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
        if failures:
            raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
