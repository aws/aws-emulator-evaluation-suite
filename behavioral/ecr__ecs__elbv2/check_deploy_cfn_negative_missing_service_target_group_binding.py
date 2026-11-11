"""deploy-cfn-negative-missing-service-target-group-binding."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-negative-missing-service-target-group-binding"
GROUP = "iac-stack-negative"
SERVICES = ["ecr", "ecs", "elbv2"]

# No docker CLI is available in this environment; the stack wires an ECR pull-through cache
# rule for the public ECR registry instead of `docker push`-ing a locally built image. The
# FIRST pull of `<acct>.dkr.ecr.<region>.amazonaws.com/<prefix>/nginx/nginx:<tag>` synchronously
# fetches and caches `public.ecr.aws/nginx/nginx:<tag>` -- no local docker needed.
_UPSTREAM_REGISTRY_URL = "public.ecr.aws"


@tags(
    "axis:negative-delivery",
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
    """An ECS service created WITHOUT the LoadBalancers property never registers with the ALB
    target group, even though its tasks run fine -- while a sibling service in the same stack
    that DOES set LoadBalancers registers and becomes healthy on that same target group."""
    vpc_id, subnet_ids = _network_vpc_and_subnets(ctx)

    prefix = _xname(ctx, "pt")
    cluster_name = _xname(ctx, "cl")
    family = _xname(ctx, "fam")
    service_no_lb = _xname(ctx, "svc-no-lb")
    service_with_lb = _xname(ctx, "svc-with-lb")

    _register_ptc_repo_cleanup(ctx, prefix)

    template = _build_app_template(
        prefix, cluster_name, family, service_no_lb, service_with_lb
    )
    app_stack = _deploy_cfn(
        ctx,
        template,
        parameters={
            "VpcId": vpc_id,
            "SubnetA": subnet_ids[0],
            "SubnetB": subnet_ids[1],
            "ImageTag": "latest",
        },
        timeout_s=900,
    )
    tg_arn = app_stack["outputs"]["TargetGroupArn"]

    ecs = ctx.client("ecs")
    elbv2 = ctx.client("elbv2")

    no_lb_ips = _poll_until(
        lambda: _task_private_ips(ctx, cluster_name, service_no_lb),
        lambda ips: len(ips) >= 1,
        timeout_s=180.0,
        interval_s=10.0,
        description="LoadBalancers-less service has a RUNNING task",
    )
    with_lb_ips = _poll_until(
        lambda: _task_private_ips(ctx, cluster_name, service_with_lb),
        lambda ips: len(ips) >= 1,
        timeout_s=180.0,
        interval_s=10.0,
        description="LoadBalancers-wired service has a RUNNING task",
    )

    # Positive control (same file, same stack, same target group): the sibling service that DOES
    # set LoadBalancers must actually register and turn healthy.
    healthy_ids = _poll_until(
        lambda: {
            h["Target"]["Id"]
            for h in elbv2.describe_target_health(TargetGroupArn=tg_arn)[
                "TargetHealthDescriptions"
            ]
            if h["TargetHealth"]["State"] == "healthy"
        },
        lambda ids: any(ip in ids for ip in with_lb_ips),
        timeout_s=180.0,
        interval_s=10.0,
        description="LoadBalancers-wired service's task becomes a healthy target",
    )
    assert any(ip in healthy_ids for ip in with_lb_ips), (
        f"expected the LoadBalancers-wired service's task IPs {with_lb_ips} to be among the "
        f"healthy targets, found {healthy_ids}"
    )

    # The effect is ABSENT for the sibling that omitted LoadBalancers: its running task's IP was
    # never, and is still not, a target of the group at all (not merely unhealthy).
    all_target_ids = {
        h["Target"]["Id"]
        for h in elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
    }
    assert not (set(no_lb_ips) & all_target_ids), (
        f"expected the LoadBalancers-less service's task IPs {no_lb_ips} to never appear as "
        f"targets, found among {all_target_ids}"
    )
    no_lb_service_lbs = ecs.describe_services(
        cluster=cluster_name, services=[service_no_lb]
    )["services"][0]["loadBalancers"]
    assert no_lb_service_lbs == [], (
        f"expected the LoadBalancers-less service to report no load balancer bindings, found {no_lb_service_lbs!r}"
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
        except ClientError as exc:
            err = exc.response["Error"]
            gone = err["Code"] == "StackNotFoundException" or (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            )
            if not gone:
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


def _network_vpc_and_subnets(ctx) -> tuple[str, list[str]]:
    """The shared network's VPC and two of its subnets in distinct AZs (an internet-facing ALB
    requires multi-AZ subnets)."""
    net = ctx.network()
    subnet_ids = net.subnet_ids[:2]
    if len(subnet_ids) < 2:
        raise AssertionError(
            f"shared network lacks subnets in >=2 AZs for an internet-facing ALB: {net.subnets!r}"
        )
    return net.vpc_id, subnet_ids


def _register_ptc_repo_cleanup(
    ctx, prefix: str, image_name: str = "nginx/nginx"
) -> None:
    """The pull-through-cache rule lazily creates `<prefix>/<image_name>` on first pull; that
    repo is NOT owned by the CFN stack, so deleting the stack does not delete it."""
    ecr = ctx.client("ecr")
    repo_name = f"{prefix}/{image_name}"

    def _delete() -> None:
        try:
            ecr.delete_repository(repositoryName=repo_name, force=True)
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") != "RepositoryNotFoundException":
                raise

    ctx.on_cleanup(_delete)


def _task_private_ips(ctx, cluster: str, service_name: str) -> list[str]:
    ecs = ctx.client("ecs")
    task_arns = ecs.list_tasks(
        cluster=cluster, serviceName=service_name, desiredStatus="RUNNING"
    )["taskArns"]
    if not task_arns:
        return []
    tasks = ecs.describe_tasks(cluster=cluster, tasks=task_arns)["tasks"]
    ips: list[str] = []
    for t in tasks:
        if t.get("lastStatus") != "RUNNING":
            continue
        for att in t.get("attachments", []):
            for det in att.get("details", []):
                if det["name"] == "privateIPv4Address":
                    ips.append(det["value"])
    return ips


def _build_app_template(
    prefix: str,
    cluster_name: str,
    family: str,
    service_no_lb: str,
    service_with_lb: str,
) -> str:
    container_image_sub = (
        "${AWS::AccountId}.dkr.ecr.${AWS::Region}.amazonaws.com/"
        + prefix
        + "/nginx/nginx:${ImageTag}"
    )
    resources = {
        "PullThroughCacheRule": {
            "Type": "AWS::ECR::PullThroughCacheRule",
            "Properties": {
                "EcrRepositoryPrefix": prefix,
                "UpstreamRegistryUrl": _UPSTREAM_REGISTRY_URL,
            },
        },
        "Cluster": {
            "Type": "AWS::ECS::Cluster",
            "Properties": {"ClusterName": cluster_name, "Tags": _xsvc_tags_kv()},
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
                "Policies": [
                    {
                        "PolicyName": "PullThroughCache",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "ecr:CreateRepository",
                                        "ecr:BatchImportUpstreamImage",
                                    ],
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
                "Tags": _xsvc_tags_kv(),
            },
        },
        "TaskDef": {
            "Type": "AWS::ECS::TaskDefinition",
            "Properties": {
                "Family": family,
                "NetworkMode": "awsvpc",
                "RequiresCompatibilities": ["FARGATE"],
                "Cpu": "256",
                "Memory": "512",
                "RuntimePlatform": {
                    "CpuArchitecture": "X86_64",
                    "OperatingSystemFamily": "LINUX",
                },
                "ExecutionRoleArn": {"Fn::GetAtt": "ExecutionRole.Arn"},
                "ContainerDefinitions": [
                    {
                        "Name": "app",
                        "Image": {"Fn::Sub": container_image_sub},
                        "PortMappings": [{"ContainerPort": 80, "Protocol": "tcp"}],
                    }
                ],
                "Tags": _xsvc_tags_kv(),
            },
        },
        "AlbSecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "alb sg",
                "VpcId": {"Ref": "VpcId"},
                "Tags": _xsvc_tags_kv(),
            },
        },
        "ServiceSecurityGroup": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": "service sg",
                "VpcId": {"Ref": "VpcId"},
                "SecurityGroupIngress": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 80,
                        "ToPort": 80,
                        "SourceSecurityGroupId": {"Ref": "AlbSecurityGroup"},
                    }
                ],
                "Tags": _xsvc_tags_kv(),
            },
        },
        "LoadBalancer": {
            "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "Properties": {
                "Type": "application",
                "Scheme": "internet-facing",
                "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                "SecurityGroups": [{"Ref": "AlbSecurityGroup"}],
                "Tags": _xsvc_tags_kv(),
            },
        },
        "TargetGroup": {
            "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
            "Properties": {
                "TargetType": "ip",
                "Port": 80,
                "Protocol": "HTTP",
                "VpcId": {"Ref": "VpcId"},
                "HealthCheckPath": "/",
                "HealthCheckIntervalSeconds": 10,
                "HealthyThresholdCount": 2,
                "Tags": _xsvc_tags_kv(),
            },
        },
        "Listener": {
            "Type": "AWS::ElasticLoadBalancingV2::Listener",
            "Properties": {
                "LoadBalancerArn": {"Ref": "LoadBalancer"},
                "Port": 80,
                "Protocol": "HTTP",
                "DefaultActions": [
                    {"Type": "forward", "TargetGroupArn": {"Ref": "TargetGroup"}}
                ],
            },
        },
        # The broken sibling: a real ECS service, real running task, but no LoadBalancers wiring
        # at all -- this is the exact CFN property the scenario omits.
        "ServiceNoLb": {
            "Type": "AWS::ECS::Service",
            "DependsOn": ["Cluster", "TaskDef"],
            "Properties": {
                "ServiceName": service_no_lb,
                "Cluster": {"Ref": "Cluster"},
                "TaskDefinition": {"Ref": "TaskDef"},
                "DesiredCount": 1,
                "LaunchType": "FARGATE",
                "NetworkConfiguration": {
                    "AwsvpcConfiguration": {
                        "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                        "SecurityGroups": [{"Ref": "ServiceSecurityGroup"}],
                        "AssignPublicIp": "ENABLED",
                    }
                },
                "Tags": _xsvc_tags_kv(),
            },
        },
        # Positive control, same stack, same target group: identical task def/networking, but
        # wired to the target group as intended.
        "ServiceWithLb": {
            "Type": "AWS::ECS::Service",
            "DependsOn": ["Cluster", "TaskDef", "Listener"],
            "Properties": {
                "ServiceName": service_with_lb,
                "Cluster": {"Ref": "Cluster"},
                "TaskDefinition": {"Ref": "TaskDef"},
                "DesiredCount": 1,
                "LaunchType": "FARGATE",
                "NetworkConfiguration": {
                    "AwsvpcConfiguration": {
                        "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                        "SecurityGroups": [{"Ref": "ServiceSecurityGroup"}],
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
                "Tags": _xsvc_tags_kv(),
            },
        },
    }
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "VpcId": {"Type": "AWS::EC2::VPC::Id"},
            "SubnetA": {"Type": "AWS::EC2::Subnet::Id"},
            "SubnetB": {"Type": "AWS::EC2::Subnet::Id"},
            "ImageTag": {"Type": "String", "Default": "latest"},
        },
        "Resources": resources,
        "Outputs": {"TargetGroupArn": {"Value": {"Ref": "TargetGroup"}}},
    }
    return json.dumps(template)


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
    """Wait for the stack's deletion, then delete each task definition revision it registered.
    The stack deletion was already awaited, so this wait is short to fit the cleanup budget."""
    if stack_id is None:
        return
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 120}
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
