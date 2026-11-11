"""cfn-alb-target-group-port-mismatch-negative."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-alb-target-group-port-mismatch-negative"
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
    """An ECS service whose target group port (8080) is not the port nginx listens on (80) has targets
    that turn unhealthy and never healthy, and the ALB answers 502 on its path, while a correctly wired
    sibling service in the same stack serves nginx with 200 (positive control)."""
    net = ctx.network()
    vpc_id, subnet_ids = net.vpc_id, net.subnet_ids[:2]
    template = _template(vpc_id=vpc_id, subnet_ids=subnet_ids, ingress=ctx.ingress_cidrs())
    stack = _deploy_cfn(ctx, json.dumps(template))
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    dns_name = outputs["LoadBalancerDnsName"]
    broken_tg = outputs["BrokenTargetGroupArn"]
    good_tg = outputs["GoodTargetGroupArn"]

    ecs = ctx.client("ecs")
    broken_service = outputs["BrokenServiceName"]
    # The broken service is declared at DesiredCount=0 so the stack can stabilize; it is scaled up here.
    ecs.update_service(cluster=cluster, service=broken_service, desiredCount=1)
    # Scale back down before the stack teardown registered above runs (cleanups are LIFO), so
    # CloudFormation is never asked to delete a service that is still churning tasks.
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ecs.update_service(
                cluster=cluster, service=broken_service, desiredCount=0
            )
        )
    )
    _wait_ecs_service_steady(ctx, cluster, broken_service, desired=1)
    _wait_ecs_service_steady(ctx, cluster, outputs["GoodServiceName"], desired=1)

    # --- positive control: matching port becomes healthy and serves real traffic ---
    # Requested at "/": an ALB forward action passes the path through unchanged, so nginx would
    # answer 404 for /good/; the correctly-wired target group is the listener's default action.
    _wait_target_health(ctx, good_tg, "healthy", min_count=1, timeout_s=180)
    status, body = _http_get_retry(
        ctx, f"http://{dns_name}/", want_status=200, timeout_s=60
    )
    assert status == 200, f"expected 200 from the correctly-wired service, got {status}"
    assert "nginx" in body.lower()

    # --- negative: mismatched port never becomes healthy, no traffic is delivered ---
    # Poll until the failed health checks mark a target unhealthy; it must never read healthy.
    left = ctx.time_left()
    deadline = time.monotonic() + (90 if left is None else min(90, left))
    while True:
        descs = ctx.client("elbv2").describe_target_health(TargetGroupArn=broken_tg)[
            "TargetHealthDescriptions"
        ]
        states = {d["TargetHealth"]["State"] for d in descs}
        assert descs, (
            "the mismatched-port target group lost all its registered targets, so there is "
            "nothing to observe as unhealthy"
        )
        assert "healthy" not in states, (
            f"target group with a container-port mismatch must never report healthy, got {states}"
        )
        if "unhealthy" in states:
            break
        assert time.monotonic() < deadline, (
            f"the mismatched-port target never reported unhealthy within 90s, got {states}"
        )
        time.sleep(2)
    # 502, not 503: an ALB whose registered targets are all unhealthy fails open and forwards to
    # them, so the request reaches port 8080, where nothing listens (503 means no registered target).
    status2, _ = _http_get(ctx, f"http://{dns_name}/broken/x", timeout=10)
    assert status2 == 502, (
        f"expected 502 (ALB fails open to the unhealthy target, whose declared port nothing "
        f"listens on) for the mismatched-port path, got {status2}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "ClusterNotFoundException",
            "NamespaceNotFoundException",
            "ServiceNotFoundException",
        ):
            raise


def _stack_failure_reasons(cfn, stack_name: str) -> list[str]:
    """The per-RESOURCE reasons a stack failed. Without these, a rollback reports only
    ROLLBACK_COMPLETE, which names neither the resource nor the cause."""
    reasons: list[str] = []
    try:
        for ev in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]:
            if ev.get("ResourceStatus", "").endswith("FAILED") and ev.get("ResourceStatusReason"):
                reasons.append(f"{ev['LogicalResourceId']}: {ev['ResourceStatusReason']}")
    except ClientError as exc:
        reasons.append(f"<could not read stack events: {exc}>")
    return reasons[:10]


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
    # 720s: the stack waits for the good ECS service to stabilize (Fargate placement, image pull,
    # two passing ALB health checks), which can approach 420s; 720s keeps the worst-case total
    # (~1590s incl. teardown) under the suite's 1800s budget.
    timeout_s=720.0,
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
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}: {_stack_failure_reasons(cfn, name)}"
        )
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
    logical_id: str, trust: str, managed_policies: list[str] | None = None
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


def _service_block(
    *,
    subnet_ids,
    sg_ref: str,
    tg_ref: str,
    task_def_ref: str,
    container_port: int,
    depends_on: str,
    desired_count: int = 1,
    health_check_grace_period_seconds: int | None = None,
) -> dict[str, Any]:
    props: dict[str, Any] = {
        "Cluster": {"Ref": "Cluster"},
        "TaskDefinition": {"Ref": task_def_ref},
        "DesiredCount": desired_count,
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
                "ContainerPort": container_port,
                "TargetGroupArn": {"Ref": tg_ref},
            }
        ],
    }
    # A generous grace period on top of DesiredCount=0: the scale-up happens after the stack
    # is complete, but it keeps ECS from tearing the first task down before its (permanently
    # failing) health checks have been observed.
    if health_check_grace_period_seconds is not None:
        props["HealthCheckGracePeriodSeconds"] = health_check_grace_period_seconds
    return {"Type": "AWS::ECS::Service", "DependsOn": depends_on, "Properties": props}


def _tg_block(vpc_id: str, port: int) -> dict[str, Any]:
    return {
        "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
        "Properties": {
            "VpcId": vpc_id,
            "Port": port,
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


def _task_def_block(container_port: int) -> dict[str, Any]:
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
                    # nginx always listens on 80 regardless of what we declare here.
                    "PortMappings": [
                        {"ContainerPort": container_port, "Protocol": "tcp"}
                    ],
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


def _template(*, vpc_id: str, subnet_ids: list[str], ingress: list[str]) -> dict[str, Any]:
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
                },
            },
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    # No apostrophe: EC2 restricts GroupDescription to
                    # "a-zA-Z0-9. _-:/()#,@[]+=&;{}!$*" and rejects anything else.
                    "GroupDescription": "task sg - both candidate ports open, SG is not under test",
                    "VpcId": vpc_id,
                    "SecurityGroupIngress": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 80,
                            "ToPort": 80,
                            "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                        },
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 8080,
                            "ToPort": 8080,
                            "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                        },
                    ],
                },
            },
            "ExecutionRole": _role_block(
                "ExecutionRole",
                "ecs-tasks.amazonaws.com",
                [
                    "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                ],
            ),
            "TaskRole": _role_block("TaskRole", "ecs-tasks.amazonaws.com"),
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "BrokenTaskDef": _task_def_block(8080),
            "GoodTaskDef": _task_def_block(80),
            "BrokenTargetGroup": _tg_block(vpc_id, 8080),
            "GoodTargetGroup": _tg_block(vpc_id, 80),
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
                    # The correctly-wired target group is the DEFAULT action (see run()): an
                    # ALB forward action does not rewrite the path, so routing the positive
                    # control through a /good/* rule would hand the container a path it does
                    # not serve.
                    "DefaultActions": [
                        {"Type": "forward", "TargetGroupArn": {"Ref": "GoodTargetGroup"}}
                    ],
                },
            },
            "BrokenRule": _rule_block(1, "/broken/*", "BrokenTargetGroup"),
            "BrokenService": _service_block(
                subnet_ids=subnet_ids,
                sg_ref="TaskSecurityGroup",
                tg_ref="BrokenTargetGroup",
                task_def_ref="BrokenTaskDef",
                container_port=8080,
                depends_on="BrokenRule",
                # See run()'s docstring: 0 here, scaled to 1 by an API call after the stack
                # completes, because CloudFormation waits for an ECS service to stabilize and
                # this one is designed never to.
                desired_count=0,
                health_check_grace_period_seconds=600,
            ),
            "GoodService": _service_block(
                subnet_ids=subnet_ids,
                sg_ref="TaskSecurityGroup",
                tg_ref="GoodTargetGroup",
                task_def_ref="GoodTaskDef",
                container_port=80,
                depends_on="Listener",
            ),
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "BrokenServiceName": {"Value": {"Fn::GetAtt": ["BrokenService", "Name"]}},
            "GoodServiceName": {"Value": {"Fn::GetAtt": ["GoodService", "Name"]}},
            "BrokenTargetGroupArn": {"Value": {"Ref": "BrokenTargetGroup"}},
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
