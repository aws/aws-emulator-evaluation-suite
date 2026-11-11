"""deploy-cfn-updates-service-on-image-tag-change."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-updates-service-on-image-tag-change"
GROUP = "iac-stack"
SERVICES = ["ecr", "ecs", "elbv2"]

# No docker CLI is available in this environment; the stack wires an ECR pull-through cache
# rule for the public ECR registry instead of `docker push`-ing locally built images. Each
# distinct tag pulled under `<acct>.dkr.ecr.<region>.amazonaws.com/<prefix>/nginx/nginx:<tag>`
# is synchronously fetched from `public.ecr.aws/nginx/nginx:<tag>` on its first pull -- no local
# docker needed, and "latest" vs. "1-alpine" are genuinely different upstream images/digests.
_UPSTREAM_REGISTRY_URL = "public.ecr.aws"


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
    """Updating the ECR image tag parameter on a deployed stack rolls the ECS service to new
    tasks that re-register healthy on the same, unchanged ALB target group."""
    vpc_id, subnet_ids = _network_vpc_and_subnets(ctx)

    prefix = _xname(ctx, "pt")
    cluster_name = _xname(ctx, "cl")
    family = _xname(ctx, "fam")
    service_name = _xname(ctx, "svc")

    _register_ptc_repo_cleanup(ctx, prefix)

    template = _build_app_template(prefix, cluster_name, family, service_name)
    parameters = {
        "VpcId": vpc_id,
        "SubnetA": subnet_ids[0],
        "SubnetB": subnet_ids[1],
        "ImageTag": "latest",
    }
    app_stack = _deploy_cfn(ctx, template, parameters=parameters, timeout_s=900)
    tg_arn = app_stack["outputs"]["TargetGroupArn"]
    stack_name = app_stack["stack_name"]

    elbv2 = ctx.client("elbv2")
    ecs = ctx.client("ecs")

    def _healthy_count() -> int:
        health = elbv2.describe_target_health(TargetGroupArn=tg_arn)[
            "TargetHealthDescriptions"
        ]
        return sum(1 for t in health if t["TargetHealth"]["State"] == "healthy")

    _poll_until(
        _healthy_count,
        lambda n: n >= 1,
        timeout_s=180.0,
        interval_s=10.0,
        description="initial deploy target healthy",
    )

    initial_task_arns = set(
        ecs.list_tasks(
            cluster=cluster_name, serviceName=service_name, desiredStatus="RUNNING"
        )["taskArns"]
    )
    assert initial_task_arns, "expected at least one RUNNING task before the update"

    # Flip the stack's ImageTag parameter to a genuinely different upstream image/digest.
    parameters["ImageTag"] = "1-alpine"
    _update_stack_and_wait(ctx, stack_name, template, parameters, timeout_s=900)

    _poll_until(
        _healthy_count,
        lambda n: n >= 1,
        timeout_s=180.0,
        interval_s=10.0,
        description="post-update target healthy",
    )

    final_task_arns = set(
        ecs.list_tasks(
            cluster=cluster_name, serviceName=service_name, desiredStatus="RUNNING"
        )["taskArns"]
    )
    assert final_task_arns, "expected at least one RUNNING task after the update"
    assert final_task_arns.isdisjoint(initial_task_arns), (
        f"expected the service to redeploy onto new tasks, but {final_task_arns & initial_task_arns} persisted"
    )

    task_def = ecs.describe_services(cluster=cluster_name, services=[service_name])[
        "services"
    ][0]["taskDefinition"]
    assert task_def.endswith(f"{family}:2"), (
        f"expected task def revision 2 (image tag change), got {task_def}"
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
    try:
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
    except AssertionError as exc:
        raise AssertionError(f"{exc}; {_stack_diagnosis(ctx, name)}") from None
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(
            f"Stack {name} ended in {stack['StackStatus']}; {_stack_diagnosis(ctx, name)}"
        )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _update_stack_and_wait(
    ctx,
    stack_name: str,
    template_body: str,
    parameters: dict[str, str],
    timeout_s: float = 900.0,
) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    terminal = {
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
    }
    try:
        status = _poll_until(
            lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
            lambda s: s in terminal,
            timeout_s=timeout_s,
            interval_s=10.0,
            description=f"update stack {stack_name}",
        )
    except AssertionError as exc:
        raise AssertionError(f"{exc}; {_stack_diagnosis(ctx, stack_name)}") from None
    if status != "UPDATE_COMPLETE":
        raise AssertionError(
            f"stack update ended in {status}; {_stack_diagnosis(ctx, stack_name)}"
        )


def _stack_diagnosis(ctx, stack_name: str) -> str:
    """Why a stack has not settled: its failed resource events, and its ECS service's latest
    events and stopped-task reasons. CloudFormation holds an ECS service in CREATE_IN_PROGRESS or
    UPDATE_IN_PROGRESS until the service is stable, so a rollout whose tasks never become healthy
    surfaces only there. A read that fails is named in place of what it would have shown."""
    try:
        return _read_stack_diagnosis(ctx, stack_name)
    except ClientError as exc:
        return f"diagnosis unavailable: {exc}"


def _read_stack_diagnosis(ctx, stack_name: str) -> str:
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")
    failed = [
        f"{e['LogicalResourceId']} {e['ResourceStatus']}: {e.get('ResourceStatusReason', '')}"
        for e in cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
        if e["ResourceStatus"].endswith("_FAILED")
    ][:5]
    service_events, stopped = [], []
    for res in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]:
        if res["ResourceType"] != "AWS::ECS::Service" or not res.get("PhysicalResourceId"):
            continue
        service_arn = res["PhysicalResourceId"]
        cluster = service_arn.split("/")[-2]
        for svc in ecs.describe_services(cluster=cluster, services=[service_arn])["services"]:
            service_events += [ev["message"] for ev in svc.get("events", [])[:5]]
        arns = ecs.list_tasks(cluster=cluster, desiredStatus="STOPPED")["taskArns"][:5]
        if arns:
            stopped += [
                f"{t.get('stoppedReason')} "
                f"{[c.get('reason') for c in t.get('containers', []) if c.get('reason')]}"
                for t in ecs.describe_tasks(cluster=cluster, tasks=arns)["tasks"]
            ]
    return f"failed events={failed!r}; ECS service events={service_events!r}; stopped tasks={stopped!r}"


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


def _build_app_template(
    prefix: str, cluster_name: str, family: str, service_name: str
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
        "Service": {
            "Type": "AWS::ECS::Service",
            "DependsOn": ["Cluster", "TaskDef", "Listener"],
            "Properties": {
                "ServiceName": service_name,
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
        "Outputs": {
            "TargetGroupArn": {"Value": {"Ref": "TargetGroup"}},
            "LoadBalancerArn": {"Value": {"Ref": "LoadBalancer"}},
            "LoadBalancerDnsName": {"Value": {"Fn::GetAtt": "LoadBalancer.DNSName"}},
        },
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
