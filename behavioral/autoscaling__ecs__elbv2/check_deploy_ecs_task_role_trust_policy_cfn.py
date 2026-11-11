"""deploy-ecs-task-role-trust-policy-cfn."""

from __future__ import annotations

import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-task-role-trust-policy-cfn"
GROUP = "deploy-behavior"
SERVICES = ["autoscaling", "ecs", "elbv2"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  ServiceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: sim2real ecs task sg
      VpcId: __VPC_ID__
  ExecutionRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ecs-tasks.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
  LogGroup:
    Type: AWS::Logs::LogGroup
    Properties:
      RetentionInDays: 1
  Cluster:
    Type: AWS::ECS::Cluster
  TaskDefinition:
    Type: AWS::ECS::TaskDefinition
    Properties:
      RequiresCompatibilities: [FARGATE]
      NetworkMode: awsvpc
      Cpu: '256'
      Memory: '512'
      ExecutionRoleArn: !GetAtt ExecutionRole.Arn
      ContainerDefinitions:
        - Name: app
          Image: public.ecr.aws/docker/library/httpd:latest
          PortMappings:
            - ContainerPort: 80
              Protocol: tcp
          LogConfiguration:
            LogDriver: awslogs
            Options:
              awslogs-group: !Ref LogGroup
              awslogs-region: !Ref AWS::Region
              awslogs-stream-prefix: app
  Service:
    Type: AWS::ECS::Service
    Properties:
      Cluster: !Ref Cluster
      TaskDefinition: !Ref TaskDefinition
      DesiredCount: 1
      LaunchType: FARGATE
      NetworkConfiguration:
        AwsvpcConfiguration:
          AssignPublicIp: ENABLED
          Subnets: [__SUBNET_A__]
          SecurityGroups: [!Ref ServiceSecurityGroup]
Outputs:
  ClusterOut:
    Value: !Ref Cluster
  ServiceOut:
    Value: !Ref Service
  LogGroupOut:
    Value: !Ref LogGroup
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
    """A CloudFormation-deployed execution role trusting ecs-tasks.amazonaws.com lets ECS assume it,
    so a service using it runs a task to RUNNING."""
    vpc_id, subnets = _default_vpc_and_subnets(ctx, min_subnets=1)
    template = _TEMPLATE.replace("__VPC_ID__", vpc_id).replace(
        "__SUBNET_A__", subnets[0]
    )
    result = _deploy_cfn(ctx, template, timeout_s=400)
    cluster = result["outputs"]["ClusterOut"]
    service = result["outputs"]["ServiceOut"]
    log_group = result["outputs"]["LogGroupOut"]

    ecs = ctx.client("ecs")
    logs = ctx.client("logs")

    def _task_arns():
        return ecs.list_tasks(cluster=cluster, serviceName=service).get("taskArns", [])

    task_arns = _poll_until(
        _task_arns,
        lambda arns: len(arns) >= 1,
        timeout_s=180,
        interval_s=10.0,
        description="service places a task",
    )

    def _last_status():
        tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]
        return tasks[0]["lastStatus"] if tasks else None

    status = _poll_until(
        _last_status,
        lambda s: s in {"RUNNING", "STOPPED"},
        timeout_s=180,
        interval_s=10.0,
        description="task reaches a terminal launch state",
    )
    assert status == "RUNNING", (
        f"task ended in {status}, execution role trust likely broken"
    )

    events = _poll_until(
        lambda: logs.filter_log_events(
            logGroupName=log_group, logStreamNamePrefix="app"
        ).get("events", []),
        lambda evs: len(evs) >= 1,
        timeout_s=120,
        interval_s=10.0,
        description="execution role ships container output to CloudWatch Logs",
    )
    assert events, (
        f"expected at least one log event pushed via the execution role into {log_group}, got none"
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
