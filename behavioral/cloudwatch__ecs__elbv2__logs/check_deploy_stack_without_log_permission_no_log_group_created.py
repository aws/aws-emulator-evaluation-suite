"""deploy-stack-without-log-permission-no-log-group-created."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-without-log-permission-no-log-group-created"
GROUP = "permission-boundary"
SERVICES = ["cloudwatch", "ecs", "elbv2", "logs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With only AmazonECSTaskExecutionRolePolicy (no logs:CreateLogGroup), an awslogs-create-group
    task never creates its log group or reaches RUNNING; the same task definition with a role that
    adds logs:CreateLogGroup does both, isolating the missing permission as the cause."""
    template = json.dumps(_template())
    deployed = _deploy_cfn(ctx, template, timeout_s=300.0)
    outputs = deployed["outputs"]
    cluster_arn = outputs["ClusterArn"]
    subnets = outputs["SubnetIds"].split(",")
    sg = outputs["DefaultSgId"]
    task_def_bad = outputs["TaskDefBadArn"]
    task_def_good = outputs["TaskDefGoodArn"]
    log_group_bad = outputs["LogGroupBadName"]
    log_group_good = outputs["LogGroupGoodName"]

    ecs = ctx.client("ecs")
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_bad))
    ctx.on_cleanup(lambda: _safe_delete_log_group(logs, log_group_good))
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnets,
            "securityGroups": [sg],
            "assignPublicIp": "ENABLED",
        }
    }

    # --- missing logs:CreateLogGroup: task never reaches RUNNING, log group never created ---
    bad_run = ecs.run_task(
        cluster=cluster_arn, taskDefinition=task_def_bad, launchType="FARGATE", count=1,
        networkConfiguration=net_cfg,
    )
    assert bad_run["tasks"], f"RunTask failed synchronously: {bad_run.get('failures')}"
    bad_arn = bad_run["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: _safe_stop_task(ecs, cluster_arn, bad_arn))

    observed_statuses: list[str] = []

    def _bad_probe():
        t = ecs.describe_tasks(cluster=cluster_arn, tasks=[bad_arn])["tasks"][0]
        observed_statuses.append(t["lastStatus"])
        return t

    final_bad = _poll_until(
        _bad_probe,
        lambda t: t["lastStatus"] == "STOPPED",
        timeout_s=180.0,
        interval_s=5.0,
        description="task with a log-group-creation-forbidden execution role reaches STOPPED",
    )
    assert final_bad["lastStatus"] == "STOPPED", (
        f"expected STOPPED, got {final_bad['lastStatus']!r}"
    )
    assert "RUNNING" not in observed_statuses, (
        f"task without logs:CreateLogGroup reached RUNNING; observed: {observed_statuses}"
    )
    existing = logs.describe_log_groups(logGroupNamePrefix=log_group_bad)["logGroups"]
    assert not any(g["logGroupName"] == log_group_bad for g in existing), (
        f"log group {log_group_bad} exists despite the execution role lacking CreateLogGroup"
    )

    # --- positive control: execution role also has logs:CreateLogGroup -> group is created ---
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
        description="task with logs:CreateLogGroup permission reaches RUNNING",
    )
    assert final_good["lastStatus"] == "RUNNING", f"positive control did not reach RUNNING: {final_good}"

    created = _poll_until(
        lambda: logs.describe_log_groups(logGroupNamePrefix=log_group_good)["logGroups"],
        lambda gs: any(g["logGroupName"] == log_group_good for g in gs),
        timeout_s=60.0,
        interval_s=5.0,
        description=f"log group {log_group_good} is created by the running task",
    )
    assert any(g["logGroupName"] == log_group_good for g in created), (
        f"expected {log_group_good} among created log groups, got {[g['logGroupName'] for g in created]}"
    )
    logs.tag_log_group(logGroupName=log_group_good, tags=_xsvc_resource_tags())


def _safe_stop_task(ecs, cluster_arn: str, task_arn: str) -> None:
    try:
        ecs.stop_task(cluster=cluster_arn, task=task_arn, reason="test cleanup")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
            raise


def _safe_delete_log_group(logs, name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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
    log_group_bad = {"Fn::Sub": "/ecs/${AWS::StackName}-bad"}
    log_group_good = {"Fn::Sub": "/ecs/${AWS::StackName}-good"}

    def _container(log_group_ref: Any) -> dict[str, Any]:
        return {
            "Name": "app",
            "Image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "Essential": True,
            "Command": ["sleep", "45"],
            "LogConfiguration": {
                "LogDriver": "awslogs",
                "Options": {
                    "awslogs-group": log_group_ref,
                    "awslogs-region": {"Ref": "AWS::Region"},
                    "awslogs-stream-prefix": "app",
                    "awslogs-create-group": "true",
                },
            },
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
            "BadExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust_ecs,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            },
            "GoodExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": trust_ecs,
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "AllowCreateLogGroup",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "logs:CreateLogGroup",
                                        "Resource": "*",
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "TaskDefBad": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["BadExecRole", "Arn"]},
                    "ContainerDefinitions": [_container(log_group_bad)],
                },
            },
            "TaskDefGood": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ExecutionRoleArn": {"Fn::GetAtt": ["GoodExecRole", "Arn"]},
                    "ContainerDefinitions": [_container(log_group_good)],
                },
            },
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "TaskDefBadArn": {"Value": {"Ref": "TaskDefBad"}},
            "TaskDefGoodArn": {"Value": {"Ref": "TaskDefGood"}},
            "SubnetIds": {"Value": {"Fn::Join": [",", [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}]]}},
            "DefaultSgId": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultSecurityGroup"]}},
            "LogGroupBadName": {"Value": log_group_bad},
            "LogGroupGoodName": {"Value": log_group_good},
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
    """Register deletion of every task definition revision the stack (and nested stacks)
    registers: CloudFormation only deregisters them, leaving INACTIVE revisions. Register the
    returned cleanup after the stack's own deletion so it runs before it."""
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
