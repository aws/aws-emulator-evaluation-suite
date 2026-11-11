"""cfn-alb-listener-rule-routes-to-ecs-service-positive."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-alb-listener-rule-routes-to-ecs-service-positive"
GROUP = "traffic-routing"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:endpoint",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN-deployed listener rule forwarding a path pattern to the ECS service's target group
    delivers a request through the ALB to the task (200, nginx body); a path the rule does not
    match gets the default fixed response (404, "no-rule-matched")."""
    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:2]
    template = _template(vpc_id=vpc_id, subnet_ids=subnet_ids, ingress=ctx.ingress_cidrs())
    stack = _deploy_cfn(ctx, json.dumps(template))
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    service = outputs["ServiceName"]
    tg_arn = outputs["TargetGroupArn"]
    dns_name = outputs["LoadBalancerDnsName"]

    _wait_ecs_service_steady(ctx, cluster, service, desired=1)
    _wait_target_health(ctx, tg_arn, "healthy", min_count=1, timeout_s=240)

    # The matching path routes through the rule to the ECS task's nginx. The target
    # group already reports the target healthy, but the ALB's internal routing tables
    # can take a few more seconds to propagate that state, so retry briefly.
    status, body = _http_get_retry(
        ctx, f"http://{dns_name}/app/", want_status=200, timeout_s=60
    )
    assert status == 200, (
        f"expected 200 through the matching listener rule, got {status}"
    )
    assert "nginx" in body.lower(), (
        f"expected the nginx welcome page body, got: {body[:200]!r}"
    )

    # A path that does NOT match the rule's pattern falls through to the listener's
    # default fixed-response action, proving it was the RULE (not the default action)
    # that routed the first request to the ECS service.
    status2, body2 = _http_get(ctx, f"http://{dns_name}/nomatch", timeout=10)
    assert status2 == 404, (
        f"expected 404 from the default fixed-response action, got {status2}"
    )
    assert body2 == "no-rule-matched", (
        f"expected the default action's fixed body, got: {body2[:200]!r}"
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
        deployments = d.get("deployments") or []
        primary = next((x for x in deployments if x.get("status") == "PRIMARY"), None)
        return (
            d["runningCount"] == desired
            and primary is not None
            and primary.get("rolloutState") == "COMPLETED"
        )

    return _poll_until(
        probe,
        pred,
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"ECS service {service} steady state",
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


def _template(*, vpc_id: str, subnet_ids: list[str], ingress: list[str]) -> dict[str, Any]:
    tags = _xsvc_tags_kv()
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "AlbSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "alb sg",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "CidrIp": c,
                        }
                        for c in ingress
                    ],
                    "Tags": tags,
                },
            },
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "task sg",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                        }
                    ],
                    "Tags": tags,
                },
            },
            "ExecutionRole": {
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
                    "Tags": tags,
                },
            },
            "TaskRole": {
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
                    "Tags": tags,
                },
            },
            "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {"Tags": tags}},
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
                            "Command": [
                                "sh",
                                "-c",
                                "mkdir -p /usr/share/nginx/html/app && "
                                "cp /usr/share/nginx/html/index.html /usr/share/nginx/html/app/index.html && "
                                "exec nginx -g 'daemon off;'",
                            ],
                            "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}],
                        }
                    ],
                    "Tags": tags,
                },
            },
            "TargetGroup": {
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
                    "Tags": tags,
                },
            },
            "Alb": {
                "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
                "Properties": {
                    "Scheme": "internet-facing",
                    "Subnets": subnet_ids,
                    "SecurityGroups": [{"Ref": "AlbSecurityGroup"}],
                    "Type": "application",
                    "Tags": tags,
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
            "AppRule": {
                "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
                "Properties": {
                    "ListenerArn": {"Ref": "Listener"},
                    "Priority": 1,
                    "Conditions": [
                        {
                            "Field": "path-pattern",
                            "PathPatternConfig": {"Values": ["/app/*", "/app"]},
                        }
                    ],
                    "Actions": [
                        {"Type": "forward", "TargetGroupArn": {"Ref": "TargetGroup"}}
                    ],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "DependsOn": "AppRule",
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
                    "LoadBalancers": [
                        {
                            "ContainerName": "app",
                            "ContainerPort": 80,
                            "TargetGroupArn": {"Ref": "TargetGroup"},
                        }
                    ],
                    "Tags": tags,
                },
            },
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "ServiceName": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
            "TargetGroupArn": {"Value": {"Ref": "TargetGroup"}},
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
