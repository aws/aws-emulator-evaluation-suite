"""cfn-ecs-service-health-check-grace-period-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-service-health-check-grace-period-positive"
GROUP = "health-check"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """With a 90 s healthCheckGracePeriodSeconds, a new task revision whose container sleeps 25 s
    before listening is never STOPPED while its ALB health check fails, and the same task is then
    RUNNING and the healthy target."""
    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    sleep_s = 25
    grace_period_s = 90  # generous margin over sleep_s + nginx startup + first health check
    template = _template(
        vpc_id=vpc_id,
        subnet_ids=subnet_ids,
        grace_period=grace_period_s,
        health_check_interval=5,
        unhealthy_threshold=2,
        healthy_threshold=2,
        health_check_timeout=3,
    )
    stack = _deploy_cfn(ctx, json.dumps(template))
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    service = outputs["ServiceName"]
    tg_arn = outputs["TargetGroupArn"]
    task_role_arn = outputs["TaskRoleArn"]
    exec_role_arn = outputs["ExecutionRoleArn"]

    ecs = ctx.client("ecs")
    _wait_ecs_service_steady(ctx, cluster, service, desired=1)
    _wait_target_health(ctx, tg_arn, "healthy", min_count=1, timeout_s=180)

    # Roll a new revision whose container sleeps before listening on port 80, forcing
    # its ALB health checks to fail for `sleep_s` seconds after it starts RUNNING.
    new_family = _register_slow_start_task_def(ctx, task_role_arn, exec_role_arn, sleep_s=sleep_s)
    ecs.update_service(cluster=cluster, service=service, taskDefinition=new_family, forceNewDeployment=True)

    new_task_arn = _wait_for_new_task(ctx, cluster, service, timeout_s=90)

    # Poll across the whole sleep window: the new task must never leave RUNNING even
    # though its target health check is failing (grace period protects it).
    deadline = time.monotonic() + sleep_s + 10
    saw_running = False
    while time.monotonic() < deadline:
        t = ecs.describe_tasks(cluster=cluster, tasks=[new_task_arn])["tasks"][0]
        assert t["lastStatus"] != "STOPPED", (
            f"grace period {grace_period_s}s should have protected the new task from being "
            f"stopped due to failing health checks, but it was stopped: {t.get('stoppedReason')}"
        )
        if t["lastStatus"] == "RUNNING":
            saw_running = True
        time.sleep(3)
    assert saw_running, "new task never reached RUNNING during the observation window"

    # The task eventually becomes healthy on its own once nginx starts.
    descs = _wait_target_health(ctx, tg_arn, "healthy", min_count=1, timeout_s=120)
    healthy_ids = {d["Target"]["Id"] for d in descs if d["TargetHealth"]["State"] == "healthy"}
    final_task = ecs.describe_tasks(cluster=cluster, tasks=[new_task_arn])["tasks"][0]
    assert final_task["lastStatus"] == "RUNNING", "the same new task should still be RUNNING once healthy"
    assert _task_private_ip(final_task) in healthy_ids, "the surviving new task should be the one reporting healthy"


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=420.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    _record_stack_id = _task_definition_teardown(ctx, name)
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    ctx.on_cleanup(_record_stack_id)
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


def _get_default_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC in this account/region to attach the ALB/ECS resources to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())
    if len(subnet_ids) < 2:
        raise AssertionError("shared network does not have subnets in >=2 AZs, required by an ALB")
    return vpc_id, subnet_ids[:2]


def _wait_ecs_service_steady(ctx, cluster: str, service: str, desired: int, timeout_s: float = 360.0) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        return ecs.describe_services(cluster=cluster, services=[service])["services"][0]

    def pred(d):
        deployments = d.get("deployments") or []
        primary = next((x for x in deployments if x.get("status") == "PRIMARY"), None)
        return d["runningCount"] == desired and primary is not None and primary.get("rolloutState") == "COMPLETED"

    return _poll_until(probe, pred, timeout_s=timeout_s, interval_s=10.0, description=f"ECS service {service} steady state")


def _wait_target_health(ctx, tg_arn: str, want_state: str, *, min_count: int = 1, timeout_s: float = 240.0) -> list[dict]:
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]

    def pred(descs):
        return len([d for d in descs if d["TargetHealth"]["State"] == want_state]) >= min_count

    return _poll_until(probe, pred, timeout_s=timeout_s, interval_s=10.0, description=f"target group reach {want_state}")


def _task_private_ip(task: dict) -> str | None:
    for att in task.get("attachments", []):
        for det in att.get("details", []):
            if det.get("name") == "privateIPv4Address":
                return det.get("value")
    return None


def _register_slow_start_task_def(ctx, task_role_arn: str, exec_role_arn: str, *, sleep_s: int) -> str:
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-xsvc-slowtd-")
    resp = ecs.register_task_definition(
        family=family,
        requiresCompatibilities=["FARGATE"],
        networkMode="awsvpc",
        cpu="256",
        memory="512",
        executionRoleArn=exec_role_arn,
        taskRoleArn=task_role_arn,
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/nginx/nginx:1.27",
                "essential": True,
                "entryPoint": ["sh", "-c"],
                "command": [f"sleep {sleep_s} && nginx -g 'daemon off;'"],
                "portMappings": [{"containerPort": 80, "protocol": "tcp"}],
            }
        ],
        tags=[{"key": k, "value": v} for k, v in _xsvc_resource_tags().items()],
    )
    task_def_arn = resp["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _deregister_and_delete_task_definition(ecs, task_def_arn))
    return task_def_arn


def _wait_for_new_task(ctx, cluster: str, service: str, *, timeout_s: float = 90.0) -> str:
    ecs = ctx.client("ecs")

    def probe():
        return ecs.list_tasks(cluster=cluster, serviceName=service, desiredStatus="RUNNING")["taskArns"]

    def pred(arns):
        return len(arns) >= 1

    arns = _poll_until(probe, pred, timeout_s=timeout_s, interval_s=5.0, description="new task to appear")
    # There may briefly be 2 tasks (old + new) during the rolling replacement; the new
    # one is whichever was started most recently.
    tasks = ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
    newest = max(tasks, key=lambda t: t["startedAt"] if t.get("startedAt") else t["createdAt"])
    return newest["taskArn"]


def _template(
    *,
    vpc_id: str,
    subnet_ids: list[str],
    grace_period: int,
    health_check_interval: int,
    unhealthy_threshold: int,
    healthy_threshold: int,
    health_check_timeout: int,
) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AlbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb sg",
                    "VpcId": vpc_id,
                },
            },
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "task sg",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"}}
                    ],
                },
            },
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"],
                },
            },
            "TaskRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    }
                },
            },
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "TaskDef": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "RequiresCompatibilities": ["FARGATE"],
                    "NetworkMode": "awsvpc",
                    "Cpu": "256",
                    "Memory": "512",
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "TaskRoleArn": {"Fn::GetAtt": ["TaskRole", "Arn"]},
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": "public.ecr.aws/nginx/nginx:1.27",
                            "Essential": True,
                            "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}],
                        }
                    ],
                },
            },
            "TargetGroup": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "VpcId": vpc_id,
                    "Port": 80,
                    "Protocol": "HTTP",
                    "TargetType": "ip",
                    "HealthCheckIntervalSeconds": health_check_interval,
                    "HealthyThresholdCount": healthy_threshold,
                    "UnhealthyThresholdCount": unhealthy_threshold,
                    "HealthCheckTimeoutSeconds": health_check_timeout,
                    "HealthCheckPath": "/",
                    "HealthCheckProtocol": "HTTP",
                },
            },
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Scheme": "internet-facing",
                    "Subnets": subnet_ids,
                    "SecurityGroups": [{"Ref": "AlbSecurityGroup"}],
                    "Type": "application",
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "TargetGroup"}}],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "DependsOn": "Listener",
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "TaskDefinition": {"Ref": "TaskDef"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": subnet_ids,
                            "SecurityGroups": [{"Ref": "TaskSecurityGroup"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                    "LoadBalancers": [{"ContainerName": "app", "ContainerPort": 80, "TargetGroupArn": {"Ref": "TargetGroup"}}],
                    "HealthCheckGracePeriodSeconds": grace_period,
                },
            },
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "ServiceName": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
            "TargetGroupArn": {"Value": {"Ref": "TargetGroup"}},
            "TaskRoleArn": {"Value": {"Fn::GetAtt": ["TaskRole", "Arn"]}},
            "ExecutionRoleArn": {"Value": {"Fn::GetAtt": ["ExecutionRole", "Arn"]}},
        },
    }


def _deregister_and_delete_task_definition(ecs, arn: str) -> None:
    """Deregister the revision, then delete it: a deregistered revision stays INACTIVE."""
    ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


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
