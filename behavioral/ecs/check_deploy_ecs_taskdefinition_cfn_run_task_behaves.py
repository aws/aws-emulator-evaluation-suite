"""deploy-ecs-taskdefinition-cfn-run-task-behaves."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ecs-taskdefinition-cfn-run-task-behaves"
GROUP = "deploy"
SERVICES = ["ecs"]

_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav-td-"},
]
_ECS_TAGS = [{"key": "sim2real:managed", "value": "true"}]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-registered ECS::TaskDefinition can be RunTask'd directly by its stack-produced
    ARN, and the resulting task actually launches with the stack-defined image/command
    (not just a task-definition record that DescribeTaskDefinition echoes back)."""
    ec2 = ctx.client("ec2")
    subnet_id, sg_id = _default_subnet_and_sg(ec2, ctx=ctx)

    family = ctx.unique_name("sim2real-behav-td-")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    expected_image = "public.ecr.aws/docker/library/busybox:1.36"

    params = [{"ParameterKey": "FamilyName", "ParameterValue": family}]
    outputs = _deploy_cfn(ctx, stack_name, _TASKDEF_TEMPLATE, params)
    task_def_arn = outputs["TaskDefinitionArn"]

    ecs = ctx.client("ecs")
    described = ecs.describe_task_definition(taskDefinition=task_def_arn)["taskDefinition"]
    assert described["family"] == family, f"expected family {family}, got {described['family']}"
    actual_image = described["containerDefinitions"][0]["image"]
    assert actual_image == expected_image, f"expected image {expected_image}, got {actual_image}"
    actual_command = described["containerDefinitions"][0]["command"]
    assert actual_command == ["sh", "-c", "sleep 300"], (
        f"expected command ['sh', '-c', 'sleep 300'], got {actual_command}"
    )

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    ecs.create_cluster(clusterName=cluster_name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: _drain_and_delete_ecs_cluster(ecs, cluster_name))

    run_resp = ecs.run_task(
        cluster=cluster_name,
        taskDefinition=task_def_arn,
        launchType="FARGATE",
        count=1,
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": [subnet_id],
                "securityGroups": [sg_id],
                "assignPublicIp": "ENABLED",
            }
        },
        tags=_ECS_TAGS,
    )
    assert not run_resp.get("failures"), f"RunTask reported failures: {run_resp.get('failures')}"
    task_arn = run_resp["tasks"][0]["taskArn"]

    def _stop_task() -> None:
        try:
            ecs.stop_task(cluster=cluster_name, task=task_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                raise
        _wait_task_stopped(ecs, cluster_name, task_arn, timeout_s=120.0)

    ctx.on_cleanup(_stop_task)

    task = _wait_task_running_or_stopped(ecs, cluster_name, task_arn, timeout_s=180.0)
    assert task["lastStatus"] in ("RUNNING", "STOPPED"), (
        f"expected RUNNING or STOPPED, got {task['lastStatus']}"
    )
    if task["lastStatus"] == "STOPPED":
        raise AssertionError(
            f"task exited before reaching RUNNING; stoppedReason={task.get('stoppedReason')}"
        )
    containers = task["containers"]
    assert len(containers) == 1, f"expected exactly 1 container, got {len(containers)}"
    assert containers[0]["image"] == expected_image, (
        f"expected running container image {expected_image}, got {containers[0]['image']}"
    )
    assert containers[0]["taskArn"] == task_arn, (
        f"expected container taskArn {task_arn}, got {containers[0]['taskArn']}"
    )
    assert task["taskDefinitionArn"] == task_def_arn, (
        f"expected running task's taskDefinitionArn {task_def_arn}, got {task['taskDefinitionArn']}"
    )


# ===== helpers =====

_TASKDEF_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"FamilyName": {"Type": "String"}},
        "Resources": {
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
                            "Command": ["sh", "-c", "sleep 300"],
                            "Essential": True,
                        }
                    ],
                },
            }
        },
        "Outputs": {
            "TaskDefinitionArn": {"Value": {"Ref": "TaskDefinition"}},
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


def _deploy_cfn(ctx: Any, stack_name: str, template_body: str, parameters: list) -> dict:
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
        Tags=_TAGS,
    )
    _record_stack_id = _task_definition_teardown(ctx, stack_name)
    ctx.on_cleanup(_cleanup)
    ctx.on_cleanup(_record_stack_id)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _wait_task_running_or_stopped(
    ecs: Any, cluster: str, task_arn: str, timeout_s: float
) -> dict:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if tasks and tasks[0]["lastStatus"] in ("RUNNING", "STOPPED"):
            return tasks[0]
        time.sleep(5.0)
    raise AssertionError(f"task {task_arn} never reached RUNNING/STOPPED within {timeout_s}s")


def _wait_task_stopped(ecs: Any, cluster: str, task_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
        tasks = resp.get("tasks", [])
        if not tasks or tasks[0]["lastStatus"] == "STOPPED":
            return
        time.sleep(5.0)



def _drain_and_delete_ecs_cluster(ecs, cluster, timeout_s=900.0, interval_s=10.0):
    """Stop a cluster's services and tasks, wait until the tasks have stopped, then delete it.

    DeleteCluster is refused while services, tasks or container instances remain, and a task's
    ENI stays in the shared network until the task has stopped, which keeps the network from
    being deleted.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s

    def arns(op, key, **kw):
        return [a for page in ecs.get_paginator(op).paginate(cluster=cluster, **kw) for a in page.get(key, [])]

    try:
        services = arns("list_services", "serviceArns")
    except ClientError as e:
        if e.response["Error"]["Code"] == "ClusterNotFoundException":
            return
        raise
    for service in services:
        for call in (
            lambda s=service: ecs.update_service(cluster=cluster, service=s, desiredCount=0),
            lambda s=service: ecs.delete_service(cluster=cluster, service=s, force=True),
        ):
            try:
                call()
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "ClusterNotFoundException",
                    "ServiceNotFoundException",
                    "ServiceNotActiveException",
                ):
                    raise
    while True:
        for task in arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            try:
                ecs.stop_task(cluster=cluster, task=task, reason="sim2real teardown")
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                    raise
        stopping = arns("list_tasks", "taskArns", desiredStatus="STOPPED")
        live = []
        for i in range(0, len(stopping), 100):
            live += [t for t in ecs.describe_tasks(cluster=cluster, tasks=stopping[i:i + 100])["tasks"]
                     if t.get("lastStatus") != "STOPPED"]
        if not live and not arns("list_tasks", "taskArns", desiredStatus="RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise AssertionError(f"{len(live)} task(s) in {cluster} still not STOPPED after {timeout_s:.0f}s")
        time.sleep(interval_s)
    while True:
        try:
            ecs.delete_cluster(cluster=cluster)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ClusterNotFoundException":
                return
            if code == "ClusterContainsContainerInstancesException":
                for instance in arns("list_container_instances", "containerInstanceArns"):
                    try:
                        ecs.deregister_container_instance(cluster=cluster, containerInstance=instance, force=True)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ClusterNotFoundException":
                            raise
            elif code not in (
                "ClusterContainsTasksException",
                "ClusterContainsServicesException",
                "UpdateInProgressException",
                "ResourceInUseException",
            ):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

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
