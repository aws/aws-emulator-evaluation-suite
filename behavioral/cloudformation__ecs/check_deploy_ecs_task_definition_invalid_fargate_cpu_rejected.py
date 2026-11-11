"""deploy-ecs-task-definition-invalid-fargate-cpu-rejected."""
from __future__ import annotations

import json
import re
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ecs-task-definition-invalid-fargate-cpu-rejected"
GROUP = "deploy-cfn-resource-existence"
SERVICES = ["cloudformation", "ecs"]

CONTAINER_NAME = "app"
CONTAINER_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
# Not one of Fargate's fixed task-level (cpu, memory) pairs: ECS rejects it before registering
# anything.
BAD_CPU = "100"
GOOD_CPU = "256"
MEMORY = "512"

# ECS's error as the task-definition handler relays it, optionally inside CloudFormation's
# resource-handler wrapper; the request id and token vary.
_REASON = re.compile(
    r'^(?:Resource handler returned message: ")?(?P<message>.*) \(Service: [A-Za-z0-9]+; '
    r"Status Code: (?P<status>\d+); Error Code: (?P<code>[A-Za-z0-9.]+); Request ID: [^;)]*; "
    r'Proxy: null\)(?:" \(RequestToken: [^,]*, HandlerErrorCode: [A-Za-z]+\))?$'
)


def _template(family: str, cpu: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TaskDef": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
                "Family": family,
                "RequiresCompatibilities": ["FARGATE"],
                "NetworkMode": "awsvpc",
                "Cpu": cpu,
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


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A Fargate task definition naming a cpu value outside Fargate's fixed (cpu, memory) pairs is
    rejected by ECS before anything is registered; the identical shape with a valid pair succeeds.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    bad_family = ctx.unique_name("sim2real-xsvc-ecstdbad-")
    bad_name = ctx.unique_name("sim2real-xsvc-ecstdbadstack-")
    bad_stack_id = cfn.create_stack(
        StackName=bad_name, TemplateBody=json.dumps(_template(bad_family, BAD_CPU)),
        Tags=[{"Key": "sim2real", "Value": bad_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, bad_stack_id))

    bad_stack = _wait_create(cfn, bad_stack_id)
    assert bad_stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"a Fargate task definition with cpu={BAD_CPU!r} ended {bad_stack['StackStatus']!r}, "
        f"expected 'ROLLBACK_COMPLETE'"
    )
    events = cfn.describe_stack_events(StackName=bad_stack_id)["StackEvents"]
    failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
    assert [e["LogicalResourceId"] for e in failed] == ["TaskDef"], (
        f"expected exactly the task definition to fail creation; CREATE_FAILED events were "
        f"{[(e['LogicalResourceId'], e.get('ResourceStatusReason')) for e in failed]!r}"
    )
    reason = failed[0].get("ResourceStatusReason") or ""
    match = _REASON.match(reason)
    assert match is not None, f"the task definition failure reason is not an ECS error: {reason!r}"
    got_error = (match["message"], match["status"], match["code"])
    want_error = (
        "Invalid request provided: Create TaskDefinition: Invalid 'cpu' setting for task. For more "
        "information, see the Troubleshooting section of the Amazon ECS Developer Guide.",
        "400",
        "ClientException",
    )
    assert got_error == want_error, f"CREATE_FAILED reason: expected {want_error!r}, got {got_error!r}"

    # Effect-absent: RegisterTaskDefinition itself refused, so no revision, active or
    # deregistered, was ever minted for this family.
    for status in ("ACTIVE", "INACTIVE"):
        listed = ecs.list_task_definitions(familyPrefix=bad_family, status=status)["taskDefinitionArns"]
        assert listed == [], f"expected no {status} revisions for {bad_family!r}, found {listed!r}"

    _delete_stack_and_wait(cfn, bad_stack_id)

    # Positive control: the identical shape with a valid Fargate (cpu, memory) pair succeeds.
    good_family = ctx.unique_name("sim2real-xsvc-ecstdgood-")
    good_name = ctx.unique_name("sim2real-xsvc-ecstdgoodstack-")
    good_stack_id = cfn.create_stack(
        StackName=good_name, TemplateBody=json.dumps(_template(good_family, GOOD_CPU)),
        Tags=[{"Key": "sim2real", "Value": good_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))

    good_stack = _wait_create(cfn, good_stack_id)
    assert good_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the same shape with cpu={GOOD_CPU!r} ended {good_stack['StackStatus']!r} "
        f"({good_stack.get('StackStatusReason')!r}), expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good_stack.get("Outputs", [])}
    control_arn = outputs["TaskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, control_arn))
    control = ecs.describe_task_definition(taskDefinition=control_arn)["taskDefinition"]
    assert control["cpu"] == GOOD_CPU, f"control task definition cpu is {control['cpu']!r}"
    assert control["family"] == good_family, (
        f"control task definition family is {control['family']!r}, expected {good_family!r}"
    )

    # The stack delete deregisters the revision; the cleanup above deletes it.
    _delete_stack_and_wait(cfn, good_stack_id)
    after = ecs.describe_task_definition(taskDefinition=control_arn)["taskDefinition"]
    assert after["status"] == "INACTIVE", (
        f"the control revision must be INACTIVE after its stack delete, got {after['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
