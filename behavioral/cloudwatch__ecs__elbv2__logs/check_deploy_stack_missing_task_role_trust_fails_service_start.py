"""deploy-stack-missing-task-role-trust-fails-service-start."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-missing-task-role-trust-fails-service-start"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Negative: an ECS task whose task role does not trust ecs-tasks.amazonaws.com stops instead
    of reaching RUNNING, while the same family with a correct trust policy in the same stack runs,
    so the rejection is specific to the broken trust relationship."""
    template = json.dumps(_template())
    deployed = _deploy_cfn(ctx, template, timeout_s=300.0)
    outputs = deployed["outputs"]
    cluster_arn = outputs["ClusterArn"]
    subnets = outputs["SubnetIds"].split(",")
    sg = outputs["DefaultSgId"]
    task_def_bad = outputs["TaskDefBadArn"]
    task_def_good = outputs["TaskDefGoodArn"]

    ecs = ctx.client("ecs")
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    # --- broken trust: task must never reach RUNNING. ECS may reject this synchronously
    # (RunTask raises because it cannot assume TaskRoleArn) or the task may launch and then
    # never make it past PENDING/STOPPED -- either is valid evidence of the missing trust.
    observed_statuses: list[str] = []
    synchronous_rejection = False
    try:
        bad_run = ecs.run_task(
            cluster=cluster_arn, taskDefinition=task_def_bad, launchType="FARGATE", count=1,
            networkConfiguration=net_cfg,
        )
    except ClientError as exc:
        synchronous_rejection = True
        assert "assume" in str(exc).lower() or "role" in str(exc).lower(), (
            f"unexpected RunTask failure mode for broken trust policy: {exc}"
        )
    else:
        if not bad_run["tasks"]:
            synchronous_rejection = True
            assert bad_run.get("failures"), (
                f"RunTask returned neither a task nor a failure: {bad_run}"
            )
        else:
            bad_arn = bad_run["tasks"][0]["taskArn"]
            ctx.on_cleanup(lambda: _safe_stop_task(ecs, cluster_arn, bad_arn))

            def _bad_probe():
                t = ecs.describe_tasks(cluster=cluster_arn, tasks=[bad_arn])["tasks"][0]
                observed_statuses.append(t["lastStatus"])
                return t

            final_bad = _poll_until(
                _bad_probe,
                lambda t: t["lastStatus"] == "STOPPED",
                timeout_s=180.0,
                interval_s=5.0,
                description="task with broken task-role trust policy reaches STOPPED",
            )
            assert final_bad["lastStatus"] == "STOPPED"
            assert "RUNNING" not in observed_statuses, (
                f"task with a broken trust policy reached RUNNING; observed statuses: "
                f"{observed_statuses}"
            )

    assert synchronous_rejection or observed_statuses, (
        "broken task-role trust policy did not produce any observable rejection"
    )


    # --- positive control: same setup, correct trust policy -> reaches RUNNING ---
    good_run = ecs.run_task(
        cluster=cluster_arn, taskDefinition=task_def_good, launchType="FARGATE", count=1,
        networkConfiguration=net_cfg,
    )
    assert good_run["tasks"], f"RunTask failed synchronously: {good_run.get('failures')}"
    good_arn = good_run["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _safe_stop_task(ecs, cluster_arn, good_arn))

    final_good = _poll_until(
        lambda: ecs.describe_tasks(cluster=cluster_arn, tasks=[good_arn])["tasks"][0],
        lambda t: t["lastStatus"] in {"RUNNING", "STOPPED"},
        timeout_s=180.0,
        interval_s=5.0,
        description="task with correct task-role trust policy reaches RUNNING",
    )
    assert final_good["lastStatus"] == "RUNNING", (
        f"positive control did not reach RUNNING: {final_good}"
    )


def _safe_stop_task(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="test cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _template() -> dict[str, Any]:
    trust_ecs = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    trust_ec2 = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    container = {
        "Name": "app",
        "Image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "Essential": True,
        "Command": ["sleep", "60"],
    }
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
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust_ecs,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            },
            "BadTaskRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": trust_ec2},
            },
            "GoodTaskRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": trust_ecs},
            },
            "TaskDefBad": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "TaskRoleArn": {"Fn::GetAtt": ["BadTaskRole", "Arn"]},
                    "ContainerDefinitions": [container],
                },
            },
            "TaskDefGood": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "TaskRoleArn": {"Fn::GetAtt": ["GoodTaskRole", "Arn"]},
                    "ContainerDefinitions": [container],
                },
            },
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "TaskDefBadArn": {"Value": {"Ref": "TaskDefBad"}},
            "TaskDefGoodArn": {"Value": {"Ref": "TaskDefGood"}},
            "SubnetIds": {"Value": {"Fn::Join": [",", [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]]}},
            "DefaultSgId": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultSecurityGroup"]}},
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
        timeout_s=120,
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
    # Bounded with the stack's own 120 s deletion wait inside the suite's 900 s cleanup budget.
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
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
