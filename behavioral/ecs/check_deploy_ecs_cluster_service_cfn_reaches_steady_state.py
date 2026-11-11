"""deploy-ecs-cluster-service-cfn-reaches-steady-state."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-cluster-service-cfn-reaches-steady-state"
GROUP = "deploy"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack with ECS::Cluster + ECS::TaskDefinition + ECS::Service reaches steady
    state (RunningCount == DesiredCount) after CREATE_COMPLETE, not merely CREATE_COMPLETE."""
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _default_subnet_and_sg(ec2, ctx=ctx)

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    family = ctx.unique_name("sim2real-behav-td-")
    service_name = ctx.unique_name("sim2real-behav-svc-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")

    params = [
        {"ParameterKey": "ClusterName", "ParameterValue": cluster_name},
        {"ParameterKey": "FamilyName", "ParameterValue": family},
        {"ParameterKey": "ServiceName", "ParameterValue": service_name},
        {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
        {"ParameterKey": "SecurityGroupId", "ParameterValue": sg_id},
    ]
    _deploy_cfn(ctx, stack_name, _CLUSTER_SERVICE_TEMPLATE, params)

    ecs = ctx.client("ecs")
    deadline = time.monotonic() + 360.0
    last: tuple[int, int] | None = None
    while time.monotonic() < deadline:
        resp = ecs.describe_services(cluster=cluster_name, services=[service_name])
        services = resp.get("services", [])
        if services:
            svc = services[0]
            last = (svc["runningCount"], svc["desiredCount"])
            if (
                svc["status"] == "ACTIVE"
                and svc["desiredCount"] > 0
                and svc["runningCount"] == svc["desiredCount"]
            ):
                clusters = ecs.describe_clusters(clusters=[cluster_name])["clusters"]
                assert clusters, f"cluster {cluster_name!r} missing from DescribeClusters"
                assert clusters[0]["status"] == "ACTIVE", (
                    f"expected cluster status ACTIVE, got {clusters[0]['status']!r}"
                )
                assert clusters[0]["runningTasksCount"] >= svc["runningCount"], (
                    f"cluster runningTasksCount={clusters[0]['runningTasksCount']} "
                    f"< service runningCount={svc['runningCount']}"
                )
                return
        time.sleep(5.0)
    raise AssertionError(
        f"service never reached steady state; last (runningCount, desiredCount)={last}"
    )


# ===== helpers =====

_CLUSTER_SERVICE_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ClusterName": {"Type": "String"},
            "FamilyName": {"Type": "String"},
            "ServiceName": {"Type": "String"},
            "SubnetId": {"Type": "String"},
            "SecurityGroupId": {"Type": "String"},
        },
        "Resources": {
            "Cluster": {
                "Type": "AWS::ECS::Cluster",
                "Properties": {"ClusterName": {"Ref": "ClusterName"}},
            },
            "TaskDefinition": {
                "Type": "AWS::ECS::TaskDefinition",
                "Properties": {
                    "Family": {"Ref": "FamilyName"},
                    "Cpu": "256",
                    "Memory": "512",
                    "NetworkMode": "awsvpc",
                    "RequiresCompatibilities": ["FARGATE"],
                    "ContainerDefinitions": [
                        {
                            "Name": "app",
                            "Image": "public.ecr.aws/docker/library/busybox:1.36",
                            "Command": ["sleep", "3600"],
                            "Essential": True,
                        }
                    ],
                },
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "DependsOn": ["Cluster", "TaskDefinition"],
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "ServiceName": {"Ref": "ServiceName"},
                    "TaskDefinition": {"Ref": "TaskDefinition"},
                    "DesiredCount": 1,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": [{"Ref": "SubnetId"}],
                            "SecurityGroups": [{"Ref": "SecurityGroupId"}],
                            "AssignPublicIp": "ENABLED",
                        }
                    },
                },
            },
        },
    }
)


def _default_subnet_and_sg(ec2: Any, *, ctx) -> tuple[str, str]:

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("account/region has no shared network VPC to attach the Fargate task to")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    public = [s for s in subnets if s.get("MapPublicIpOnLaunch")]
    subnet_id = (public or subnets)[0]["SubnetId"]
    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return subnet_id, sgs[0]["GroupId"]


def _deploy_cfn(ctx: Any, stack_name: str, template_body: str, parameters: list) -> None:
    cfn = ctx.client("cloudformation")

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters,
        OnFailure="DELETE",
    )
    _record_stack_id = _task_definition_teardown(ctx, stack_name)
    ctx.on_cleanup(_cleanup)
    ctx.on_cleanup(_record_stack_id)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )


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
