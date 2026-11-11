"""deploy-ecs-task-definition-read-back-and-deregistered."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ecs-task-definition-read-back-and-deregistered"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ecs"]

CONTAINER_NAME = "app"
CONTAINER_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
CPU = "256"
MEMORY = "512"


def _template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TaskDef": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
                "RequiresCompatibilities": ["FARGATE"],
                "NetworkMode": "awsvpc",
                "Cpu": CPU,
                "Memory": MEMORY,
                "ContainerDefinitions": [{
                    "Name": CONTAINER_NAME,
                    "Image": CONTAINER_IMAGE,
                    "Essential": True,
                }],
            }},
        },
        "Outputs": {
            "TaskDefinitionArn": {"Value": {"Fn::GetAtt": ["TaskDef", "TaskDefinitionArn"]}},
        },
    }


def _wait_create(cfn, stack_id: str, max_attempts: int = 150) -> dict[str, Any]:
    try:
        cfn.get_waiter("stack_create_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _delete_stack_and_wait(cfn, stack_id: str, max_attempts: int = 150) -> None:
    cfn.delete_stack(StackName=stack_id)
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts})
    except WaiterError:
        pass
    final = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    if final["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(
            f"stack {stack_id} delete ended {final['StackStatus']!r}: "
            f"{final.get('StackStatusReason')!r}"
        )


def _retire_task_definition(ecs, task_definition_arn: str) -> None:
    """Deregister then delete a task definition revision; an already-gone one is fine."""
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition_arn)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_definition_arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-registered ECS task definition reads back through DescribeTaskDefinition with the
    template's container, cpu, memory and GetAtt ARN. Deleting the stack deregisters it, which
    ECS reports as its own INACTIVE status rather than making the ARN unreadable.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    name = ctx.unique_name("sim2real-xsvc-ecstd-")
    stack_id = cfn.create_stack(
        StackName=name, TemplateBody=json.dumps(_template()),
        Tags=[{"Key": "sim2real", "Value": name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_id))

    stack = _wait_create(cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), "
        f"expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    arn = outputs["TaskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, arn))

    physical = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="TaskDef")["StackResourceDetail"]["PhysicalResourceId"]
    assert physical == arn, (
        f"the resource's PhysicalResourceId {physical!r} disagrees with its own Fn::GetAtt "
        f"TaskDefinitionArn {arn!r}"
    )

    td = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert td["taskDefinitionArn"] == arn, (
        f"ECS describes {td['taskDefinitionArn']!r} for the ARN we asked for, expected {arn!r}"
    )
    assert td["status"] == "ACTIVE", f"a freshly-registered task definition reports {td['status']!r}"
    assert td["networkMode"] == "awsvpc", f"networkMode is {td['networkMode']!r}, expected 'awsvpc'"
    assert td["cpu"] == CPU, f"cpu is {td['cpu']!r}, expected {CPU!r}"
    assert td["memory"] == MEMORY, f"memory is {td['memory']!r}, expected {MEMORY!r}"
    assert td["requiresCompatibilities"] == ["FARGATE"], (
        f"requiresCompatibilities is {td['requiresCompatibilities']!r}, expected ['FARGATE']"
    )
    containers = td["containerDefinitions"]
    assert len(containers) == 1, f"expected exactly one container definition, got {containers!r}"
    container = containers[0]
    assert container["name"] == CONTAINER_NAME, (
        f"container name is {container['name']!r}, expected {CONTAINER_NAME!r}"
    )
    assert container["image"] == CONTAINER_IMAGE, (
        f"container image is {container['image']!r}, expected {CONTAINER_IMAGE!r}"
    )
    assert container["essential"] is True, f"container essential is {container['essential']!r}"

    _delete_stack_and_wait(cfn, stack_id)
    final = ecs.describe_task_definition(taskDefinition=arn)["taskDefinition"]
    assert final["taskDefinitionArn"] == arn, (
        f"ECS does not describe the deregistered definition by its own ARN: {final!r}"
    )
    assert final["status"] == "INACTIVE", (
        f"expected the deregistered task definition to report status 'INACTIVE', ECS reports "
        f"{final['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
