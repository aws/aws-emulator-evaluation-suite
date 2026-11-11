"""deploy-cfn-ecs-cluster-service-with-ecr-image-and-cloudwatch-logs."""

from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-ecs-cluster-service-with-ecr-image-and-cloudwatch-logs"
GROUP = "iac-stack"
SERVICES = ["cloudwatch", "ecr", "ecs"]

# A publicly pullable image hosted on the Amazon ECR Public gallery. Using an ECR Public image
# (rather than building/pushing to a private repo, which would require a docker daemon that may
# not exist in the harness) still exercises "ECS task definition references an ECR image URI" --
# ECR Public IS Amazon ECR -- while keeping the check runnable anywhere.
_IMAGE = "public.ecr.aws/amazonlinux/amazonlinux:2023"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:metrics",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CFN-deployed ECS cluster+service pulls an ECR-hosted image, the task reaches RUNNING, and
    its stdout is actually streamed into the CloudWatch Logs log group configured in the template."""
    net = _check_network(ctx)
    cluster_name = _xname(ctx, "cluster")
    service_name = _xname(ctx, "svc")
    family_name = _xname(ctx, "taskdef")
    log_group_name = f"/sim2real/{_xname(ctx, 'logs')}"
    role_name = _xname(ctx, "exec-role")
    token = f"sim2real-log-token-{uuid.uuid4().hex[:12]}"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "SecurityGroupId": {"Type": "AWS::EC2::SecurityGroup::Id"},
        },
        "Resources": {
            "LogGroup": {
                "Type": "AWS::Logs::LogGroup",
                "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1},
            },
            "Cluster": {
                "Type": "AWS::ECS::Cluster",
                "Properties": {"ClusterName": cluster_name},
            },
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            },
            "TaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Family": family_name,
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": _IMAGE,
                            "Essential": True,
                            "Command": ["sh", "-c", f"echo {token}; sleep 900"],
                            "LogConfiguration": {
                                "LogDriver": "awslogs",
                                "Options": {
                                    "awslogs-group": {"Ref": "LogGroup"},
                                    "awslogs-region": ctx.region,
                                    "awslogs-stream-prefix": "ecs",
                                },
                            },
                        }
                    ],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "DependsOn": ["TaskDefinition"],
                "Properties": {
                    "ServiceName": service_name,
                    "Cluster": {"Ref": "Cluster"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "TaskDefinition": {"Ref": "TaskDefinition"},
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": {"Ref": "SubnetIds"},
                            "SecurityGroups": [{"Ref": "SecurityGroupId"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                },
            },
        },
    }

    _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "SubnetIds": ",".join(net["subnet_ids"]),
            "SecurityGroupId": net["security_group_id"],
        },
        timeout_s=420.0,
    )
    ctx.on_cleanup(lambda: _scale_down_and_wait(ctx, cluster_name, service_name))

    ecs = ctx.client("ecs")

    def _running_task_arn() -> str | None:
        arns = ecs.list_tasks(cluster=cluster_name, serviceName=service_name).get(
            "taskArns", []
        )
        if not arns:
            return None
        tasks = ecs.describe_tasks(cluster=cluster_name, tasks=arns)["tasks"]
        for t in tasks:
            if t["lastStatus"] == "RUNNING":
                return t["taskArn"]
        return None

    task_arn = _poll_until(
        _running_task_arn,
        lambda a: a is not None,
        timeout_s=180.0,
        interval_s=5.0,
        description="ECS task reaching RUNNING",
    )
    task_id = task_arn.split("/")[-1]
    stream_name = f"ecs/app/{task_id}"

    logs = ctx.client("logs")

    def _fetch_messages() -> list[str]:
        try:
            events = logs.get_log_events(
                logGroupName=log_group_name,
                logStreamName=stream_name,
                startFromHead=True,
            )["events"]
        except ClientError:
            return []
        return [e["message"] for e in events]

    messages = _poll_until(
        _fetch_messages,
        lambda msgs: any(token in m for m in msgs),
        timeout_s=90.0,
        interval_s=5.0,
        description=f"log token {token!r} appearing in {log_group_name}/{stream_name}",
    )
    assert any(token in m for m in messages), (
        f"token {token!r} never observed in log stream"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=600,
        interval_s=5.0,
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
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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


def _check_network(ctx):
    net = _create_network(ctx, n_subnets=2)
    return {**net, "security_group_id": net["sg_id"]}


def _create_network(ctx, n_subnets: int = 1) -> dict:
    """A VPC this check owns: public subnets behind an internet gateway (Fargate pulls the image
    over a public IP) and a security group with only the default allow-all egress rule. One
    cleanup tears the whole network down in dependency order, retrying while ECS still holds
    task ENIs in it."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-net-")

    def tag(kind):
        return [{"ResourceType": kind, "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]}]

    net: dict = {"subnet_ids": []}
    net["vpc_id"] = ec2.create_vpc(CidrBlock="10.77.0.0/16", TagSpecifications=tag("vpc"))["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_network(ctx, net))
    ec2.get_waiter("vpc_available").wait(VpcIds=[net["vpc_id"]], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    net["igw_id"] = ec2.create_internet_gateway(TagSpecifications=tag("internet-gateway"))[
        "InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    net["igw_attached"] = True
    net["rt_id"] = ec2.create_route_table(VpcId=net["vpc_id"], TagSpecifications=tag("route-table"))[
        "RouteTable"]["RouteTableId"]
    ec2.create_route(RouteTableId=net["rt_id"], DestinationCidrBlock="0.0.0.0/0", GatewayId=net["igw_id"])
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-type", "Values": ["availability-zone"]}]
    )["AvailabilityZones"]]
    if len(zones) < n_subnets:
        raise AssertionError(f"need {n_subnets} availability zones, the region offers {zones}")
    for i, zone in enumerate(sorted(zones)[:n_subnets]):
        subnet_id = ec2.create_subnet(
            VpcId=net["vpc_id"], CidrBlock=f"10.77.{i}.0/24", AvailabilityZone=zone, TagSpecifications=tag("subnet")
        )["Subnet"]["SubnetId"]
        net["subnet_ids"].append(subnet_id)
        ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
        ec2.associate_route_table(RouteTableId=net["rt_id"], SubnetId=subnet_id)
    net["subnet_id"] = net["subnet_ids"][0]
    net["sg_id"] = ec2.create_security_group(
        GroupName=name, Description="sim2real check network", VpcId=net["vpc_id"], TagSpecifications=tag("security-group")
    )["GroupId"]
    return net


def _delete_network(ctx, net: dict, timeout_s: float = 900.0) -> None:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + timeout_s

    def retrying(fn, **kwargs):
        while True:
            try:
                fn(**kwargs)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code.endswith(".NotFound") or code == "Gateway.NotAttached":
                    return
                if code != "DependencyViolation" or time.monotonic() > deadline:
                    raise
            time.sleep(15)

    if net.get("sg_id"):
        retrying(ec2.delete_security_group, GroupId=net["sg_id"])
    for subnet_id in net["subnet_ids"]:
        retrying(ec2.delete_subnet, SubnetId=subnet_id)
    if net.get("rt_id"):
        retrying(ec2.delete_route_table, RouteTableId=net["rt_id"])
    if net.get("igw_attached"):
        retrying(ec2.detach_internet_gateway, InternetGatewayId=net["igw_id"], VpcId=net["vpc_id"])
    if net.get("igw_id"):
        retrying(ec2.delete_internet_gateway, InternetGatewayId=net["igw_id"])
    retrying(ec2.delete_vpc, VpcId=net["vpc_id"])


def _scale_down_and_wait(ctx, cluster: str, service: str) -> None:
    """Drain the service's tasks before the stack delete tears down the cluster/service (teardown
    helper; registered so it runs, LIFO, before _delete_stack_and_wait)."""
    ecs = ctx.client("ecs")
    try:
        ecs.update_service(cluster=cluster, service=service, desiredCount=0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotFoundException",
        ):
            raise
        return

    def _running_count() -> int:
        try:
            services = ecs.describe_services(cluster=cluster, services=[service])["services"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
            return 0
        return services[0]["runningCount"] if services else 0

    _poll_until(_running_count, lambda c: c == 0, timeout_s=120.0, interval_s=2.0)


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
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
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
