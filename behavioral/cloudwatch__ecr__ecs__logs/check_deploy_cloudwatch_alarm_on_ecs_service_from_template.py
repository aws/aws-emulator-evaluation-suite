"""deploy-cloudwatch-alarm-on-ecs-service-from-template."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudwatch-alarm-on-ecs-service-from-template"
GROUP = "deploy-integration"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CFN-provisioned CPUUtilization alarm on an ECS service carries the template's dimensions
    and thresholds, and SetAlarmState transitions it and records the change in alarm history."""
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")
    net = _get_network(ctx)

    template = _build_template()
    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={"SubnetId": net["subnet_id"], "SecurityGroupId": net["sg_id"]},
        timeout_s=300.0,
    )
    stack_name = result["stack_name"]
    outputs = result["outputs"]
    cluster_name = outputs["ClusterName"]
    alarm_name = outputs["AlarmName"]
    service_name = f"{stack_name}-svc"

    # Service exists (DesiredCount=0 so it stabilizes fast without pulling any image).
    svc = ecs.describe_services(cluster=cluster_name, services=[service_name])[
        "services"
    ][0]
    assert svc["status"] == "ACTIVE", (
        f"expected service {service_name} status ACTIVE, got {svc['status']!r}"
    )

    alarm = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert alarm["Namespace"] == "AWS/ECS", (
        f"expected alarm namespace AWS/ECS, got {alarm['Namespace']!r}"
    )
    assert alarm["MetricName"] == "CPUUtilization", (
        f"expected alarm metric CPUUtilization, got {alarm['MetricName']!r}"
    )
    assert alarm["Threshold"] == 80.0, (
        f"expected alarm threshold 80.0, got {alarm['Threshold']!r}"
    )
    assert alarm["ComparisonOperator"] == "GreaterThanThreshold", (
        f"expected comparison operator GreaterThanThreshold, got {alarm['ComparisonOperator']!r}"
    )
    dims = {d["Name"]: d["Value"] for d in alarm["Dimensions"]}
    expected_dims = {"ClusterName": cluster_name, "ServiceName": service_name}
    assert dims == expected_dims, (
        f"expected alarm dimensions {expected_dims}, got {dims}"
    )

    cw.set_alarm_state(
        AlarmName=alarm_name,
        StateValue="ALARM",
        StateReason="sim2real forced transition",
    )
    _poll_until(
        lambda: cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0][
            "StateValue"
        ],
        lambda s: s == "ALARM",
        timeout_s=60.0,
        interval_s=3.0,
        description="alarm ALARM transition",
    )

    history = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", MaxRecords=20
    )["AlarmHistoryItems"]
    recorded = False
    for item in history:
        data = json.loads(item["HistoryData"])
        if data.get("newState", {}).get("stateValue") == "ALARM":
            recorded = True
            break
    assert recorded is True, (
        f"expected alarm history for {alarm_name} to record a transition to ALARM: {history}"
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
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
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


def _get_network(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get(
        "Vpcs", []
    )
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; this check relies on the shared network's "
            "public shared-network subnets for the Fargate service's awsvpc networking and does not "
            "provision a custom VPC/IGW/route-table stack to stay lean"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    ).get("Subnets", [])
    if not subnets:
        raise AssertionError("shared network has no shared-network subnet available")
    subnet_id = subnets[0]["SubnetId"]
    sg = ec2.create_security_group(
        GroupName=_xname(ctx, "sg"),
        Description="sim2real behavioral check SG",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _xsvc_tags_kv()}],
    )
    sg_id = sg["GroupId"]
    ctx.on_cleanup(lambda: _delete_sg_with_retry(ec2, sg_id))
    return {"vpc_id": vpc_id, "subnet_id": subnet_id, "sg_id": sg_id}


def _delete_sg_with_retry(ec2, sg_id: str, attempts: int = 8) -> None:
    for i in range(attempts):
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as err:
            if (
                err.response["Error"]["Code"] != "DependencyViolation"
                or i == attempts - 1
            ):
                raise
            time.sleep(10.0)


def _build_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetId": {"Type": "AWS::EC2::Subnet::Id"},
            "SecurityGroupId": {"Type": "AWS::EC2::SecurityGroup::Id"},
        },
        "Resources": {
            "Cluster": {"Type": "AWS::ECS::Cluster", "Properties": {}},
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
                },
            },
            "TaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Family": {"Fn::Sub": "${AWS::StackName}-task"},
                    "RequiresCompatibilities": ["FARGATE"],
                    "NetworkMode": "awsvpc",
                    "Cpu": "256",
                    "Memory": "512",
                    "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                            "Essential": True,
                            "Command": ["/bin/sh", "-c", "sleep 3600"],
                        }
                    ],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "Properties": {
                    "ServiceName": {"Fn::Sub": "${AWS::StackName}-svc"},
                    "Cluster": {"Ref": "Cluster"},
                    "TaskDefinition": {"Ref": "TaskDefinition"},
                    # DesiredCount=0: the alarm-wiring test doesn't need a running task, and
                    # skipping the image pull keeps the deploy fast and free of network flakiness.
                    "DesiredCount": 0,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "AssignPublicIp": "ENABLED",
                            "Subnets": [{"Ref": "SubnetId"}],
                            "SecurityGroups": [{"Ref": "SecurityGroupId"}],
                        }
                    },
                },
            },
            "ServiceAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": {"Fn::Sub": "${AWS::StackName}-cpu-alarm"},
                    "Namespace": "AWS/ECS",
                    "MetricName": "CPUUtilization",
                    "Dimensions": [
                        {"Name": "ClusterName", "Value": {"Ref": "Cluster"}},
                        {
                            "Name": "ServiceName",
                            "Value": {"Fn::Sub": "${AWS::StackName}-svc"},
                        },
                    ],
                    "Statistic": "Average",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 80,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData": "notBreaching",
                },
            },
        },
        "Outputs": {
            "ClusterName": {"Value": {"Ref": "Cluster"}},
            "AlarmName": {"Value": {"Ref": "ServiceAlarm"}},
        },
    }


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
