"""cfn-ecs-task-role-missing-trust-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-task-role-missing-trust-policy-negative"
GROUP = "iam-trust"
SERVICES = ["cloudformation", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Fargate task whose task role trusts states.amazonaws.com, not ecs-tasks.amazonaws.com, stops
    with a stoppedReason before RUNNING and its container never exits; a sibling task definition
    differing only in the trust principal runs and exits 0 (positive control)."""
    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    template = _template(vpc_id=vpc_id)
    stack = _deploy_cfn(ctx, json.dumps(template))
    outputs = stack["outputs"]
    cluster = outputs["ClusterName"]
    net_cfg = {
        "awsvpcConfiguration": {
            "subnets": subnet_ids,
            "securityGroups": [outputs["SecurityGroupId"]],
            "assignPublicIp": "ENABLED",
        }
    }
    ecs = ctx.client("ecs")

    # --- negative: broken task role trust ---
    # ECS validates the task role's trust policy synchronously as part of RunTask: it
    # never gets far enough to place a task, it fails the call outright with a
    # ClientException naming the role it could not assume.
    bad_task_arn = None
    bad_run_task_error: ClientError | None = None
    try:
        bad_task_arn = ecs.run_task(
            cluster=cluster, taskDefinition=outputs["BadTaskDefArn"], launchType="FARGATE", count=1, networkConfiguration=net_cfg
        )["tasks"][0]["taskArn"]
    except ClientError as exc:
        bad_run_task_error = exc

    if bad_run_task_error is not None:
        msg = str(bad_run_task_error)
        assert "unable to assume" in msg.lower() or "assumerole" in msg.lower() or "access" in msg.lower(), (
            f"expected RunTask to fail because ECS could not assume the badly-trusted task role, got: {msg}"
        )
    else:
        ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster, task=bad_task_arn))
        bad_seen_statuses, bad_final = _observe_task_until_stopped(ctx, cluster, bad_task_arn, timeout_s=180)
        assert "RUNNING" not in bad_seen_statuses, (
            f"task with a task role that does not trust ecs-tasks.amazonaws.com must never reach "
            f"RUNNING (its container must never actually start); observed statuses: {bad_seen_statuses}"
        )
        assert bad_final["lastStatus"] == "STOPPED"
        assert bad_final["containers"][0].get("exitCode") is None, (
            "the broken-trust task's container must never have run (no exit code), got "
            f"{bad_final['containers'][0].get('exitCode')}"
        )
        assert bad_final.get("stoppedReason"), "expected a non-empty stoppedReason explaining the launch failure"

    # --- positive control: identical task definition, correct task role trust ---
    good_task_arn = ecs.run_task(
        cluster=cluster, taskDefinition=outputs["GoodTaskDefArn"], launchType="FARGATE", count=1, networkConfiguration=net_cfg
    )["tasks"][0]["taskArn"]
    ctx.on_cleanup(lambda: ecs.stop_task(cluster=cluster, task=good_task_arn))
    # The container only echoes, so RUNNING can pass between two samples; exit code 0 is the proof
    # that it started and ran.
    _good_seen_statuses, good_final = _observe_task_until_stopped(ctx, cluster, good_task_arn, timeout_s=180)
    assert good_final["containers"][0].get("exitCode") == 0, (
        f"positive control (correct task role trust) must run and exit 0, got "
        f"{good_final['containers'][0].get('exitCode')} reason={good_final['containers'][0].get('reason')}"
    )


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
        timeout_s=180,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        raise AssertionError("no shared network VPC in this account/region to launch the standalone tasks into")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return vpc_id, [s["SubnetId"] for s in subnets[:2]]


def _observe_task_until_stopped(ctx, cluster: str, task_arn: str, *, timeout_s: float = 180.0) -> tuple[set[str], dict]:
    ecs = ctx.client("ecs")
    seen: set[str] = set()
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        seen.add(last["lastStatus"])
        for c in last["containers"]:
            seen.add(c["lastStatus"])
        if last["lastStatus"] == "STOPPED":
            return seen, last
        time.sleep(4.0)
    raise AssertionError(f"task {task_arn} never reached STOPPED within {timeout_s}s; last={last}")


def _task_def(role_name_suffix: str, task_role_trust: str) -> dict[str, Any]:
    return {
        "Type": "AWS::ECS::TaskDefinition",
        "Properties": {
            "RequiresCompatibilities": ["FARGATE"],
            "NetworkMode": "awsvpc",
            "Cpu": "256",
            "Memory": "512",
            "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
            "TaskRoleArn": {"Fn::GetAtt": [f"TaskRole{role_name_suffix}", "Arn"]},
            "ContainerDefinitions": [
                {
                    "Name": "app",
                    "Image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                    "Essential": True,
                    "EntryPoint": ["sh", "-c"],
                    "Command": [f"echo hello-from-{role_name_suffix.lower()}-task"],
                }
            ],
        },
    }


def _template(*, vpc_id: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TaskSecurityGroup": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {"GroupDescription": "standalone task sg", "VpcId": vpc_id},
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
            # Broken: trusts a service that is not ECS at all.
            "TaskRoleBad": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    }
                },
            },
            # Control: correctly trusts ecs-tasks.amazonaws.com.
            "TaskRoleGood": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ecs-tasks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
                    }
                },
            },
            "Cluster": {"Type": "AWS::ECS::Cluster"},
            "BadTaskDef": _task_def("Bad", "states.amazonaws.com"),
            "GoodTaskDef": _task_def("Good", "ecs-tasks.amazonaws.com"),
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "BadTaskDefArn": {"Value": {"Ref": "BadTaskDef"}},
            "GoodTaskDefArn": {"Value": {"Ref": "GoodTaskDef"}},
            "SecurityGroupId": {"Value": {"Ref": "TaskSecurityGroup"}},
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
