"""cfn-security-group-blocks-alb-to-ecs-traffic-negative."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-security-group-blocks-alb-to-ecs-traffic-negative"
GROUP = "network-boundary"
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
    """A task security group with no ingress from the ALB's security group blocks its health
    checks, so the target never becomes healthy and no traffic is delivered; a sibling service
    differing only in that ingress rule is the positive control and serves traffic."""
    template = _template(ctx.ingress_cidrs())
    # The stack waits for both ECS services to stabilize, which takes several minutes.
    stack = _deploy_cfn(ctx, json.dumps(template), timeout_s=1080.0)
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    dns_name = outputs["LoadBalancerDnsName"]
    blocked_tg = outputs["BlockedTargetGroupArn"]
    open_tg = outputs["OpenTargetGroupArn"]

    # The SG-blocked service is created outside the stack: CloudFormation waits for an ECS
    # service's deployment to complete, which a target that can never turn healthy never does,
    # so a stack holding it stays CREATE_IN_PROGRESS for hours.
    blocked_service = _create_blocked_service(
        ctx, cluster, outputs["BlockedTaskDefinitionArn"], outputs["SubnetIds"].split(","),
        outputs["BlockedSecurityGroupId"], blocked_tg,
    )
    _wait_ecs_service_steady(ctx, cluster, blocked_service, desired=1)
    _wait_ecs_service_steady(ctx, cluster, outputs["OpenServiceName"], desired=1)

    # --- positive control: SG allows ALB ingress -> healthy + serves traffic ---
    _wait_target_health(ctx, open_tg, "healthy", min_count=1, timeout_s=180)
    status, body = _http_get_retry(
        ctx, f"http://{dns_name}/", want_status=200, timeout_s=60
    )
    assert status == 200, f"expected 200 through the open-SG service, got {status}"
    assert "nginx" in body.lower(), (
        f"expected the nginx default page through the open-SG service, got body={body[:200]!r}"
    )

    # --- negative: SG blocks ALB ingress -> never healthy, no traffic delivered ---
    # The blocked target's own health checks run and fail: it turns unhealthy, never healthy.
    left = ctx.time_left()
    descs = _wait_target_health(ctx, blocked_tg, "unhealthy", min_count=1,
                                timeout_s=180.0 if left is None else min(180.0, left))
    states = {d["TargetHealth"]["State"] for d in descs}
    assert "healthy" not in states, (
        f"target behind an SG lacking ALB ingress must never report healthy, got {states}"
    )
    # The ALB waits its 10 s target connect timeout before it answers 504, so the client waits
    # well past it rather than racing it.
    status2, _ = _http_get(ctx, f"http://{dns_name}/blocked/", timeout=30)
    # With every target unhealthy the ALB fails open and forwards to them anyway; the task SG
    # drops the connection, so real AWS answers 504 (gateway timeout), not 503.
    assert status2 == 504, (
        f"expected 504 (the ALB's forward to the SG-blocked target times out) for the "
        f"SG-blocked path, got {status2}"
    )


# ===== helpers =====

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
        except ClientError as e:
            if "does not exist" in e.response["Error"].get("Message", ""):
                return "GONE"
            raise

    # Draining the ECS services and their task ENIs before the VPC goes takes several minutes.
    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=1200,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if _status() == "DELETE_FAILED":
        failed = [
            f"{e['LogicalResourceId']}: {e.get('ResourceStatusReason')}"
            for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            if e["ResourceStatus"] == "DELETE_FAILED"
        ][:5]
        raise AssertionError(f"stack {stack_name} ended DELETE_FAILED: {failed}")


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
        failed = [
            f"{e['LogicalResourceId']} ({e.get('ResourceStatusReason', 'no reason')})"
            for e in cfn.describe_stack_events(StackName=name)["StackEvents"]
            if e["ResourceStatus"].endswith("_FAILED")
        ]
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}: {failed}")
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
        interval_s=2.0,
        description=f"target group reach {want_state}",
    )


def _http_get(ctx, url: str, *, timeout: float = 10.0) -> tuple[int, str]:
    _url, _route = ctx.endpoint_route(url)
    req = urllib.request.Request(_url, method="GET", headers=_route)
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


def _create_blocked_service(ctx, cluster, task_def_arn, subnet_ids, sg_id, tg_arn) -> str:
    """The SG-blocked service, with the same shape as the stack's open one; its generous grace
    period keeps ECS from replacing its never-healthy task."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-xsvc-blocked-svc-")
    ecs.create_service(
        cluster=cluster,
        serviceName=name,
        taskDefinition=task_def_arn,
        desiredCount=1,
        launchType="FARGATE",
        networkConfiguration={"awsvpcConfiguration": {
            "subnets": subnet_ids, "securityGroups": [sg_id], "assignPublicIp": "ENABLED",
        }},
        loadBalancers=[{"containerName": "app", "containerPort": 80, "targetGroupArn": tg_arn}],
        healthCheckGracePeriodSeconds=600,
    )

    def _delete():
        # Gone (and its task stopped) before the stack deletes the cluster, target group and VPC.
        try:
            ecs.delete_service(cluster=cluster, service=name, force=True)
        except ClientError as e:
            if e.response["Error"]["Code"] not in ("ServiceNotFoundException", "ServiceNotActiveException"):
                raise
        ecs.get_waiter("services_inactive").wait(
            cluster=cluster, services=[name], WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    ctx.on_cleanup(_delete)
    return name


def _service_block(
    *,
    subnet_ids,
    sg_ref: str,
    tg_ref: str,
    task_def_ref: str,
    depends_on: str,
) -> dict[str, Any]:
    props: dict[str, Any] = {
        "Cluster": {"Ref": "Cluster"},
        "TaskDefinition": {"Ref": task_def_ref},
        "DesiredCount": 1,
        "LaunchType": "FARGATE",
        "NetworkConfiguration": {
            "AwsvpcConfiguration": {
                "Subnets": subnet_ids,
                "SecurityGroups": [{"Ref": sg_ref}],
                "AssignPublicIp": "ENABLED",
            }
        },
        "LoadBalancers": [
            {
                "ContainerName": "app",
                "ContainerPort": 80,
                "TargetGroupArn": {"Ref": tg_ref},
            }
        ],
    }
    return {"Type": "AWS::ECS::Service", "DependsOn": depends_on, "Properties": props}


def _tg_block(vpc_id: str) -> dict[str, Any]:
    return {
        "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
        "Properties": {
            "VpcId": vpc_id,
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


def _rule_block(priority: int, path: str, tg_ref: str) -> dict[str, Any]:
    return {
        "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
        "Properties": {
            "ListenerArn": {"Ref": "Listener"},
            "Priority": priority,
            "Conditions": [
                {"Field": "path-pattern", "PathPatternConfig": {"Values": [path]}}
            ],
            "Actions": [{"Type": "forward", "TargetGroupArn": {"Ref": tg_ref}}],
        },
    }


def _template(ingress_cidrs: list[str]) -> dict[str, Any]:
    vpc_id = {"Ref": "Vpc"}
    subnet_ids = [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            # A dedicated VPC/subnets, never the account's ambient default VPC: a freshly
            # provisioned or already-mutated account may not have one with subnets in >=2 AZs,
            # which is what an ALB requires.
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/16",
                    "EnableDnsSupport": True,
                    "EnableDnsHostnames": True,
                },
            },
            "InternetGateway": {"Type": "AWS::EC2::InternetGateway"},
            "VpcGatewayAttachment": {
                "Type": "AWS::EC2::VPCGatewayAttachment",
                "Properties": {
                    "VpcId": vpc_id,
                    "InternetGatewayId": {"Ref": "InternetGateway"},
                },
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": vpc_id,
                    "CidrBlock": "10.0.0.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": vpc_id,
                    "CidrBlock": "10.0.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "MapPublicIpOnLaunch": True,
                },
            },
            "RouteTable": {
                "Type": "AWS::EC2::RouteTable",
                "Properties": {"VpcId": vpc_id},
            },
            "DefaultRoute": {
                "Type": "AWS::EC2::Route",
                "DependsOn": "VpcGatewayAttachment",
                "Properties": {
                    "RouteTableId": {"Ref": "RouteTable"},
                    "DestinationCidrBlock": "0.0.0.0/0",
                    "GatewayId": {"Ref": "InternetGateway"},
                },
            },
            "SubnetARouteTableAssociation": {
                "Type": "AWS::EC2::SubnetRouteTableAssociation",
                "Properties": {
                    "SubnetId": {"Ref": "SubnetA"},
                    "RouteTableId": {"Ref": "RouteTable"},
                },
            },
            "SubnetBRouteTableAssociation": {
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
                    "VpcId": vpc_id,
                    # The runner reaches the ALB on port 80 from these ranges only.
                    "SecurityGroupIngress": [
                        {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": cidr}
                        for cidr in ingress_cidrs
                    ],
                },
            },
            # No SecurityGroupIngress at all: default-deny, ALB cannot reach these tasks.
            "BlockedTaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "blocked task sg", "VpcId": vpc_id},
            },
            "OpenTaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "open task sg",
                    "VpcId": vpc_id,
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
            "BlockedTaskDef": _task_def_block(),
            "OpenTaskDef": _task_def_block(),
            "BlockedTargetGroup": _tg_block(vpc_id),
            "OpenTargetGroup": _tg_block(vpc_id),
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "DependsOn": [
                    "SubnetARouteTableAssociation",
                    "SubnetBRouteTableAssociation",
                ],
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
            "BlockedRule": _rule_block(1, "/blocked/*", "BlockedTargetGroup"),
            # nginx serves its default page only at "/", so the open service's rule matches the root.
            "OpenRule": _rule_block(2, "/", "OpenTargetGroup"),
            "OpenService": _service_block(
                subnet_ids=subnet_ids,
                sg_ref="OpenTaskSecurityGroup",
                tg_ref="OpenTargetGroup",
                task_def_ref="OpenTaskDef",
                depends_on="OpenRule",
            ),
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "BlockedTaskDefinitionArn": {"Value": {"Ref": "BlockedTaskDef"}},
            "BlockedSecurityGroupId": {"Value": {"Ref": "BlockedTaskSecurityGroup"}},
            "SubnetIds": {"Value": {"Fn::Join": [",", subnet_ids]}},
            "OpenServiceName": {"Value": {"Fn::GetAtt": ["OpenService", "Name"]}},
            "BlockedTargetGroupArn": {"Value": {"Ref": "BlockedTargetGroup"}},
            "OpenTargetGroupArn": {"Value": {"Ref": "OpenTargetGroup"}},
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
