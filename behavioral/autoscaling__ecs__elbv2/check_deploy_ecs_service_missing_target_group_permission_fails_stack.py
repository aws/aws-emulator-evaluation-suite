"""deploy-ecs-service-missing-target-group-permission-fails-stack."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-service-missing-target-group-permission-fails-stack"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_TEMPLATE_POSITIVE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SharedSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real alb+instance sg (positive)
      VpcId: __VPC_ID__
  SharedSecurityGroupSelfIngress:
    Type: AWS::EC2::SecurityGroupIngress
    Properties:
      GroupId: !Ref SharedSecurityGroup
      IpProtocol: tcp
      FromPort: 0
      ToPort: 65535
      SourceSecurityGroupId: !Ref SharedSecurityGroup
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
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: __CLUSTER_NAME__
  ContainerInstance:
    Type: AWS::EC2::Instance
    Properties:
      ImageId: '{{resolve:ssm:/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id}}'
      InstanceType: t3.micro
      SubnetId: __SUBNET_A__
      SecurityGroupIds:
        - !Ref SharedSecurityGroup
      IamInstanceProfile: !Ref InstanceProfile
      Tags:
        - Key: Name
          Value: sim2real-xsvc-permboundary-instance-pos
        - Key: sim2real:managed
          Value: 'true'
      UserData:
        Fn::Base64: |
          #!/bin/bash
          echo ECS_CLUSTER=__CLUSTER_NAME__ >> /etc/ecs/ecs.config
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [EC2]
      NetworkMode: bridge
      ContainerDefinitions:
        - Name: app
          Image: public.ecr.aws/docker/library/httpd:latest
          Cpu: 128
          Memory: 128
          PortMappings:
            - ContainerPort: 80
              HostPort: 0
              Protocol: tcp
  TargetGroupPositive:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: __VPC_ID__
      Port: 80
      Protocol: HTTP
      TargetType: instance
      HealthCheckPath: /
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internet-facing
      Subnets: [__SUBNET_A__, __SUBNET_B__]
      SecurityGroups: [!Ref SharedSecurityGroup]
  ListenerPositive:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Port: 80
      Protocol: HTTP
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref TargetGroupPositive
  ServicePositive:
    Type: AWS::ECS::Service
    DependsOn: [Cluster, ListenerPositive, ContainerInstance]
    Properties:
      ServiceName: __SVC_POS_NAME__
      Cluster: __CLUSTER_NAME__
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 1
      LaunchType: EC2
      LoadBalancers:
        - ContainerName: app
          ContainerPort: 80
          TargetGroupArn: !Ref TargetGroupPositive
Outputs:
  TargetGroupPositiveArn:
    Value: !Ref TargetGroupPositive
"""

_TEMPLATE_NEGATIVE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SharedSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real alb+instance sg (negative)
      VpcId: __VPC_ID__
  BrokenElbRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ecs.amazonaws.com
            Action: sts:AssumeRole
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: __CLUSTER_NAME__
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [EC2]
      NetworkMode: bridge
      ContainerDefinitions:
        - Name: app
          Image: public.ecr.aws/docker/library/httpd:latest
          Cpu: 128
          Memory: 128
          PortMappings:
            - ContainerPort: 80
              HostPort: 0
              Protocol: tcp
  TargetGroupNegative:
    Type: AWS::ElasticLoadBalancingV2::TargetGroup
    Properties:
      VpcId: __VPC_ID__
      Port: 80
      Protocol: HTTP
      TargetType: instance
      HealthCheckPath: /
  LoadBalancer:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      Scheme: internet-facing
      Subnets: [__SUBNET_A__, __SUBNET_B__]
      SecurityGroups: [!Ref SharedSecurityGroup]
  ListenerNegative:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      LoadBalancerArn: !Ref LoadBalancer
      Port: 8080
      Protocol: HTTP
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref TargetGroupNegative
  ServiceNegative:
    Type: AWS::ECS::Service
    DependsOn: [Cluster, ListenerNegative]
    Properties:
      ServiceName: __SVC_NEG_NAME__
      Cluster: __CLUSTER_NAME__
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 1
      LaunchType: EC2
      Role: !Ref BrokenElbRole
      LoadBalancers:
        - ContainerName: app
          ContainerPort: 80
          TargetGroupArn: !Ref TargetGroupNegative
Outputs:
  TargetGroupNegativeArn:
    Value: !Ref TargetGroupNegative
"""


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An ECS service whose role has no permissions fails CreateService, so its stack fails with no
    target registered; a sibling stack using the service-linked role registers its targets."""
    net = ctx.network()
    vpc_id, subnets = net.vpc_id, net.subnet_ids[:2]
    cluster_name_pos = _xname(ctx, "permclusterpos")
    cluster_name_neg = _xname(ctx, "permclusterneg")
    svc_pos_name = _xname(ctx, "svcpos")
    svc_neg_name = _xname(ctx, "svcneg")

    positive_template = (
        _TEMPLATE_POSITIVE.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
        .replace("__CLUSTER_NAME__", cluster_name_pos)
        .replace("__SVC_POS_NAME__", svc_pos_name)
    )
    negative_template = (
        _TEMPLATE_NEGATIVE.replace("__VPC_ID__", vpc_id)
        .replace("__SUBNET_A__", subnets[0])
        .replace("__SUBNET_B__", subnets[1])
        .replace("__CLUSTER_NAME__", cluster_name_neg)
        .replace("__SVC_NEG_NAME__", svc_neg_name)
    )

    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")

    # (c) positive control: the service-linked role registers the running task's instance.
    pos_result = _deploy_cfn(ctx, positive_template, timeout_s=400)
    tg_pos_arn = pos_result["outputs"]["TargetGroupPositiveArn"]

    container_instance_arns = _poll_until(
        lambda: ecs.list_container_instances(cluster=cluster_name_pos).get(
            "containerInstanceArns", []
        ),
        lambda arns: len(arns) >= 1,
        timeout_s=240,
        interval_s=10.0,
        description="container instance registers with the positive cluster",
    )
    _poll_until(
        lambda: ecs.describe_services(
            cluster=cluster_name_pos, services=[svc_pos_name]
        )["services"][0]["runningCount"],
        lambda n: n == 1,
        timeout_s=240,
        interval_s=10.0,
        description="positive service's task reaches RUNNING",
    )
    positive_targets = _poll_until(
        lambda: elbv2.describe_target_health(TargetGroupArn=tg_pos_arn)[
            "TargetHealthDescriptions"
        ],
        lambda targets: len(targets) >= 1,
        timeout_s=180,
        interval_s=10.0,
        description="positive-control target group registers a target",
    )
    registered_instance_ids = {
        ci["ec2InstanceId"]
        for ci in ecs.describe_container_instances(
            cluster=cluster_name_pos, containerInstances=container_instance_arns
        )["containerInstances"]
    }
    assert positive_targets[0]["Target"]["Id"] in registered_instance_ids, (
        f"target {positive_targets[0]['Target']['Id']!r} registered in the target group is not "
        f"one of the positive cluster's own container instances {registered_instance_ids!r}"
    )
    assert positive_targets[0]["TargetHealth"]["State"] != "unused", (
        f"target health state is 'unused' (never actually registered): {positive_targets[0]['TargetHealth']!r}"
    )

    # (a)+(b) the specific failure: the negative stack's own creation fails synchronously
    # (CreateService rejects the permission-less role before placing any task), so its
    # target group never registers anything.
    neg_status = _deploy_cfn_expect_failure(ctx, negative_template, timeout_s=400)
    assert neg_status["status"] in {
        "CREATE_FAILED",
        "ROLLBACK_COMPLETE",
        "ROLLBACK_FAILED",
    }, f"negative stack unexpectedly succeeded: {neg_status}"
    reasons = " | ".join(neg_status["failed_resources"]).lower()
    assert "role" in reasons or "permission" in reasons or "assume" in reasons, (
        f"no failed resource mentions the role/permission boundary: {neg_status['failed_resources']}"
    )

    services = ecs.describe_services(cluster=cluster_name_neg, services=[svc_neg_name])[
        "services"
    ]
    running = [
        s
        for s in services
        if s["status"] not in ("INACTIVE", "DRAINING") and s.get("runningCount", 0) > 0
    ]
    assert running == [], f"negative service unexpectedly has running tasks: {running}"


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
    _record_stack_id_2 = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(_record_stack_id_2)
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
