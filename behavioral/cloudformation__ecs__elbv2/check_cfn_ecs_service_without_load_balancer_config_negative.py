"""cfn-ecs-service-without-load-balancer-config-negative."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-service-without-load-balancer-config-negative"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags(
    "axis:negative-delivery",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """An ECS service deployed without a `loadBalancers` block registers no target in the target
    group although its task is RUNNING, while a sibling service in the same stack that declares
    loadBalancers serves nginx with 200 through the ALB (positive control)."""
    template = _template(ctx.ingress_cidrs())
    stack = _deploy_cfn(ctx, json.dumps(template))
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    dns_name = outputs["LoadBalancerDnsName"]
    pre_existing_tg = outputs["PreExistingTargetGroupArn"]
    good_tg = outputs["GoodTargetGroupArn"]

    ecs = ctx.client("ecs")
    _wait_ecs_service_steady(ctx, cluster, outputs["NoLbServiceName"], desired=1)
    _wait_ecs_service_steady(ctx, cluster, outputs["GoodServiceName"], desired=1)

    # The no-loadBalancers service is otherwise perfectly healthy: its own task runs.
    task_arns = ecs.list_tasks(cluster=cluster, serviceName=outputs["NoLbServiceName"])[
        "taskArns"
    ]
    assert task_arns, (
        "the no-loadBalancers service should still run its own task normally"
    )
    task = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"][0]
    assert task["lastStatus"] == "RUNNING", (
        f"expected the no-loadBalancers service's task to be RUNNING, got {task['lastStatus']!r}"
    )

    # --- positive control: service WITH loadBalancers registers + serves traffic ---
    _wait_target_health(ctx, good_tg, "healthy", min_count=1, timeout_s=180)
    status, body = _http_get_retry(ctx, f"http://{dns_name}/", want_status=200, timeout_s=60)
    assert status == 200, (
        f"expected 200 through the correctly-wired service, got {status}"
    )
    assert "nginx" in body.lower(), (
        f"expected the nginx default page through the correctly-wired service, got body: {body[:300]!r}"
    )

    # --- negative: the pre-existing target group is never touched by the no-LB service ---
    # By contrast: both services are steady and the sibling's target is healthy, so a
    # registration by the no-LB service would already be visible.
    descs = ctx.client("elbv2").describe_target_health(
        TargetGroupArn=pre_existing_tg
    )["TargetHealthDescriptions"]
    assert descs == [], (
        f"a service with no loadBalancers block must never register targets in a "
        f"pre-existing target group, but found: {descs}"
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
        timeout_s=900,
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
    timeout_s=420.0,
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


def _wait_ecs_service_steady(
    ctx, cluster: str, service: str, desired: int, timeout_s: float = 360.0
) -> dict:
    ecs = ctx.client("ecs")

    def probe():
        return ecs.describe_services(cluster=cluster, services=[service])["services"][0]

    def pred(d):
        return d["runningCount"] == desired

    return _poll_until(
        probe,
        pred,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"ECS service {service} runningCount={desired}",
    )


def _wait_target_health(
    ctx, tg_arn: str, want_state: str, *, min_count: int = 1, timeout_s: float = 240.0
) -> list[dict]:
    elbv2 = ctx.client("elbv2")

    def probe():
        return elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]

    def pred(descs):
        return (
            len([d for d in descs if d["TargetHealth"]["State"] == want_state])
            >= min_count
        )

    return _poll_until(
        probe,
        pred,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"target group reach {want_state}",
    )


def _http_get(ctx, url: str, *, timeout: float = 10.0) -> tuple[int, str]:
    target, route = ctx.endpoint_route(url)
    req = urllib.request.Request(target, method="GET", headers=route)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def _http_get_retry(
    ctx, url: str, *, want_status: int, timeout_s: float = 60.0, interval_s: float = 5.0
) -> tuple[int, str]:
    """Retry an HTTP GET until it returns want_status. Target-group health can flip to
    'healthy' a few seconds before the ALB's own routing tables finish propagating that
    state, so a single request right after describe_target_health can still 503/504."""
    deadline = time.monotonic() + timeout_s
    status, body = 0, ""
    while time.monotonic() < deadline:
        status, body = _http_get(ctx, url, timeout=10)
        if status == want_status:
            return status, body
        time.sleep(interval_s)
    return status, body


def _role_block(
    trust: str, managed_policies: list[str] | None = None
) -> dict[str, Any]:
    props: dict[str, Any] = {
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    }
    if managed_policies:
        props["ManagedPolicyArns"] = managed_policies
    return {"Type": "AWS::IAM::Role", "Properties": props}


def _tg_block(vpc_ref: dict[str, Any]) -> dict[str, Any]:
    return {
        "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
        "Properties": {
            "VpcId": vpc_ref,
            "Port": 80,
            "Protocol": "HTTP",
            "TargetType": "ip",
            "HealthCheckIntervalSeconds": 15,
            "HealthyThresholdCount": 2,
            "UnhealthyThresholdCount": 2,
            "HealthCheckTimeoutSeconds": 5,
            "HealthCheckPath": "/",
            "HealthCheckProtocol": "HTTP",
        },
    }


def _task_def_block() -> dict[str, Any]:
    return {
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
    }


def _template(ingress: list[str]) -> dict[str, Any]:
    subnet_refs = [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            # Self-contained networking -- a freshly provisioned account may not have a
            # default VPC, so this stack brings its own instead of depending on one.
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.42.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "InternetGateway": {"Type": "AWS::EC2::InternetGateway"},
            "VpcGatewayAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "InternetGatewayId": {"Ref": "InternetGateway"},
                },
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.42.0.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.42.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": {"Ref": "Vpc"}},
            },
            "PublicRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "VpcGatewayAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "InternetGateway"},
                },
            },
            "SubnetARouteAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SubnetA"},
                    "RouteTableId": {"Ref": "RouteTable"},
                },
            },
            "SubnetBRouteAssoc": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SubnetB"},
                    "RouteTableId": {"Ref": "RouteTable"},
                },
            },
            "AlbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb sg",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "CidrIp": c,
                        }
                        for c in ingress
                    ],
                },
            },
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "task sg",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                        }
                    ],
                },
            },
            "ExecutionRole": _role_block(
                "ecs-tasks.amazonaws.com",
                [
                    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                ],
            ),
            "TaskRole": _role_block("ecs-tasks.amazonaws.com"),
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "NoLbTaskDef": _task_def_block(),
            "GoodTaskDef": _task_def_block(),
            # Created up front, exactly like a target group provisioned for a service
            # ahead of time -- nothing ever points ECS at it.
            "PreExistingTargetGroup": _tg_block({"Ref": "Vpc"}),
            "GoodTargetGroup": _tg_block({"Ref": "Vpc"}),
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Scheme": "internet-facing",
                    "Subnets": subnet_refs,
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
                    "DefaultActions": [
                        {
                            "Type": "fixed-response",
                            "FixedResponseConfig": {
                                "StatusCode": "404",
                                "ContentType": "text/plain",
                                "MessageBody": "no-rule-matched",
                            },
                        }
                    ],
                },
            },
            "GoodRule": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 1,
                    "Conditions": [
                        {
                            "Field": "path-pattern",
                            "PathPatternConfig": {"Values": ["/*"]},
                        }
                    ],
                    "Actions": [
                        {
                            "Type": "forward",
                            "TargetGroupArn": {"Ref": "GoodTargetGroup"},
                        }
                    ],
                },
            },
            # No loadBalancers block at all -- just a plain ECS service.
            "NoLbService": {
                "Type": "AWS::ECS::Service",
                "DependsOn": ["SubnetARouteAssoc", "SubnetBRouteAssoc"],
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "TaskDefinition": {"Ref": "NoLbTaskDef"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": subnet_refs,
                            "SecurityGroups": [{"Ref": "TaskSecurityGroup"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                },
            },
            "GoodService": {
                "Type": "AWS::ECS::Service",
                "DependsOn": ["GoodRule", "SubnetARouteAssoc", "SubnetBRouteAssoc"],
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "TaskDefinition": {"Ref": "GoodTaskDef"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": subnet_refs,
                            "SecurityGroups": [{"Ref": "TaskSecurityGroup"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                    "LoadBalancers": [
                        {
                            "ContainerName": "app",
                            "ContainerPort": 80,
                            "TargetGroupArn": {"Ref": "GoodTargetGroup"},
                        }
                    ],
                },
            },
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "NoLbServiceName": {"Value": {"Fn::GetAtt": ["NoLbService", "Name"]}},
            "GoodServiceName": {"Value": {"Fn::GetAtt": ["GoodService", "Name"]}},
            "PreExistingTargetGroupArn": {"Value": {"Ref": "PreExistingTargetGroup"}},
            "GoodTargetGroupArn": {"Value": {"Ref": "GoodTargetGroup"}},
            "LoadBalancerDnsName": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
        },
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
