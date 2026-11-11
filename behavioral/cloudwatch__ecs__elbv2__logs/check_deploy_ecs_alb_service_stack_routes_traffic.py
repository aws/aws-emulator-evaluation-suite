"""deploy-ecs-alb-service-stack-routes-traffic."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-ecs-alb-service-stack-routes-traffic"
GROUP = "iac-full-stack"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CFN stack wires an ALB target group to a Fargate ECS service; real HTTP requests
    against the ALB DNS name are routed through to the running task (not just CREATE_COMPLETE)."""
    template = json.dumps(_template(ctx.ingress_cidrs()))
    deployed = _deploy_cfn(ctx, template, timeout_s=480.0)
    outputs = deployed["outputs"]
    alb_dns = outputs["AlbDnsName"]
    tg_arn = outputs["TargetGroupArn"]
    cluster_arn = outputs["ClusterArn"]
    service_arn = outputs["ServiceArn"]

    elbv2 = ctx.client("elbv2")
    ecs = ctx.client("ecs")

    def _healthy_targets():
        resp = elbv2.describe_target_health(TargetGroupArn=tg_arn)
        return [
            d
            for d in resp["TargetHealthDescriptions"]
            if d["TargetHealth"]["State"] == "healthy"
        ]

    healthy = _poll_until(
        _healthy_targets,
        lambda t: len(t) >= 1,
        timeout_s=420.0,
        interval_s=10.0,
        description="ALB target group reports a healthy target",
    )
    assert len(healthy) >= 1, f"expected >=1 healthy target in {tg_arn}, got {healthy!r}"

    svc = ecs.describe_services(cluster=cluster_arn, services=[service_arn])["services"][0]
    assert svc["runningCount"] == 1, (
        f"expected service {service_arn} runningCount == 1, got {svc['runningCount']}"
    )

    def _http_probe():
        target, route = ctx.endpoint_route(f"http://{alb_dns}/")
        try:
            with urllib.request.urlopen(urllib.request.Request(target, headers=route), timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8", "ignore")
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            return None

    status, body = _poll_until(
        _http_probe,
        lambda r: r is not None and r[0] == 200,
        timeout_s=180.0,
        interval_s=5.0,
        description="ALB DNS name serves HTTP 200 from the routed task",
    )
    assert status == 200, f"expected HTTP 200 from {alb_dns}, got {status!r} body={body!r}"
    assert "It works" in body or "Apache" in body, (
        f"expected the routed httpd default page in the response body, got {body!r}"
    )


def _template(ingress: list[str]) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "Igw": {"Type": "AWS::EC2::InternetGateway"},
            "IgwAttach": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {"VpcId": {"Ref": "Vpc"}, "InternetGatewayId": {"Ref": "Igw"}},
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.0.2.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "RouteTable": {"Type": "AWS::EC2::RouteTable", "Properties": {"VpcId": {"Ref": "Vpc"}}},
            "Route": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "IgwAttach",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "Igw"},
                },
            },
            "AssocA": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "SubnetA"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "AssocB": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {"SubnetId": {"Ref": "SubnetB"}, "RouteTableId": {"Ref": "RouteTable"}},
            },
            "AlbSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb ingress 80",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": c} for c in ingress
                    ],
                },
            },
            "SvcSg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "service ingress from alb",
                    "VpcId": {"Ref": "Vpc"},
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "SourceSecurityGroupId": {"Ref": "AlbSg"},
                        }
                    ],
                },
            },
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Type": "application",
                    "Scheme": "internet-facing",
                    "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                    "SecurityGroups": [{"Ref": "AlbSg"}],
                },
            },
            "Tg": {
                "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
                "Properties": {
                    "Port": 80,
                    "Protocol": "HTTP",
                    "TargetType": "ip",
                    "VpcId": {"Ref": "Vpc"},
                    "HealthCheckPath": "/",
                    "HealthCheckIntervalSeconds": 10,
                    "HealthyThresholdCount": 2,
                    "UnhealthyThresholdCount": 3,
                },
            },
            "Listener": {
                "Type": "AWS::ElasticLoadBalancingV2::Listener",
                "Properties": {
                    "LoadBalancerArn": {"Ref": "Alb"},
                    "Port": 80,
                    "Protocol": "HTTP",
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": {"Ref": "Tg"}}],
                },
            },
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
            "TaskDef": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "ContainerDefinitions": [
                        {
                            "Name": "web",
                            "Image": "public.ecr.aws/docker/library/httpd:2.4",
                            "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}],
                        }
                    ],
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
                            "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                            "SecurityGroups": [{"Ref": "SvcSg"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                    "LoadBalancers": [
                        {"ContainerName": "web", "ContainerPort": 80, "TargetGroupArn": {"Ref": "Tg"}}
                    ],
                },
            },
        },
        "Outputs": {
            "AlbDnsName": {"Value": {"Fn::GetAtt": ["Alb", "DNSName"]}},
            "TargetGroupArn": {"Value": {"Ref": "Tg"}},
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "ServiceArn": {"Value": {"Ref": "Service"}},
        },
    }


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=900,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
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
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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
    # The stack's own deletion cleanup has already waited for it, so this only confirms the end state.
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
