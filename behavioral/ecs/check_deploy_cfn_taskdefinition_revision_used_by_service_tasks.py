"""deploy-cfn-taskdefinition-revision-used-by-service-tasks."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-taskdefinition-revision-used-by-service-tasks"
GROUP = "server-side"
SERVICES = ["ecs"]


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ClusterName:
    Type: String
  Family:
    Type: String
  ServiceName:
    Type: String
  Subnet1:
    Type: String
  SecurityGroupId:
    Type: String
Resources:
  Cluster:
    Type: AWS::ECS::Cluster
    Properties:
      ClusterName: !Ref ClusterName
      Tags:
        - Key: sim2real-check
          Value: !Ref AWS::StackName
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Ref Family
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ContainerDefinitions:
        - Name: main
          Image: public.ecr.aws/amazonlinux/amazonlinux:2023
          Command: ["sleep", "3600"]
          Essential: true
      Tags:
        - Key: sim2real-check
          Value: !Ref AWS::StackName
  Service:
    Type: AWS::ECS::Service
    DependsOn: TaskDef
    Properties:
      Cluster: !Ref Cluster
      ServiceName: !Ref ServiceName
      TaskDefinition: !Ref TaskDef
      DesiredCount: 1
      LaunchType: FARGATE
      NetworkConfiguration:
        AwsvpcConfiguration:
          Subnets: [!Ref Subnet1]
          SecurityGroups: [!Ref SecurityGroupId]
          AssignPublicIp: ENABLED
      Tags:
        - Key: sim2real-check
          Value: !Ref AWS::StackName
Outputs:
  ServiceNameOut:
    Value: !GetAtt Service.Name
  TaskDefArnOut:
    Value: !Ref TaskDef
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECS::TaskDefinition referenced by an AWS::ECS::Service
    produces a running task whose taskDefinitionArn is the EXACT registered revision ARN
    (not just the same family/latest revision)."""
    ecs = ctx.client("ecs")
    net = _default_network(ctx)
    _ensure_ecs_slr(ctx)


    stack_name = ctx.unique_name("sim2real-ecs-cfn-tdrev-")
    cluster_name = ctx.unique_name("sim2real-ecs-cfn-tdrev-cluster-")
    family = ctx.unique_name("sim2real-ecs-cfn-tdrev-td-")
    service_name = ctx.unique_name("sim2real-ecs-cfn-tdrev-svc-")

    outputs = _deploy_cfn(
        ctx,
        stack_name,
        _TEMPLATE,
        {
            "ClusterName": cluster_name,
            "Family": family,
            "ServiceName": service_name,
            "Subnet1": net["subnet_ids"][0],
            "SecurityGroupId": net["sg_id"],
        },
    )
    _record_stack_id = _task_definition_teardown(ctx, stack_name)
    ctx.on_cleanup(lambda: _destroy_cfn(ctx, stack_name))
    ctx.on_cleanup(_record_stack_id)

    td_arn = outputs["TaskDefArnOut"]
    assert ":" in td_arn and td_arn.rsplit(":", 1)[-1].isdigit(), f"expected a revisioned ARN, got {td_arn}"

    def _running_arns():
        return ecs.list_tasks(cluster=cluster_name, serviceName=service_name, desiredStatus="RUNNING")["taskArns"]

    arns = _poll_until(_running_arns, lambda a: len(a) == 1, timeout_s=300, interval_s=10)
    task = ecs.describe_tasks(cluster=cluster_name, tasks=arns)["tasks"][0]
    assert task["taskDefinitionArn"] == td_arn, (
        f"expected running task to use registered revision {td_arn}, got {task['taskDefinitionArn']}"
    )

    svc = ecs.describe_services(cluster=cluster_name, services=[service_name])["services"][0]
    assert svc["taskDefinition"] == td_arn, (
        f"expected service to reference registered revision {td_arn}, got {svc['taskDefinition']}"
    )


# ===== helpers =====
def _ensure_ecs_slr(ctx) -> None:
    """Make sure AWSServiceRoleForECS exists so the stack's ECS::Service resource doesn't
    hit 'Unable to assume the service linked role' on a fresh account."""
    from botocore.exceptions import ClientError

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="ecs.amazonaws.com")
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("InvalidInput",):
            raise
        return

    def _role_visible():
        try:
            iam.get_role(RoleName="AWSServiceRoleForECS")
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return False
            raise

    # wait for IAM's own read path to see the role it just created, rather than a blind sleep
    _poll_until(_role_visible, lambda visible: visible, timeout_s=60, interval_s=3)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _default_network(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    public = [s["SubnetId"] for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_ids = public or [s["SubnetId"] for s in subnets]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _deploy_cfn(ctx, stack_name, template_body, parameters):
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _destroy_cfn(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    waiter = cfn.get_waiter("stack_delete_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})


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
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 30}
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
