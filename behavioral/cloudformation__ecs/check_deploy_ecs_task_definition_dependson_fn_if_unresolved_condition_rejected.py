"""deploy-ecs-task-definition-dependson-fn-if-unresolved-condition-rejected."""
from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError, WaiterError

from behavioral_harness import tags

CHECK = "deploy-ecs-task-definition-dependson-fn-if-unresolved-condition-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ecs"]

CONTAINER_IMAGE = "public.ecr.aws/docker/library/busybox:latest"
_HEALTH_CHECK = {"Command": ["CMD-SHELL", "exit 0"], "Interval": 30, "Timeout": 5, "Retries": 3}

_UNRESOLVED_CONDITION = (
    "ValidationError",
    "Template error: unresolved condition dependency HEALTHY in Fn::If",
)


def _template(family: str, *, conditions: dict[str, Any] | None, dependency_condition: Any) -> dict:
    template: dict[str, Any] = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TaskDef": {"Type": "AWS::ECS::TaskDefinition", "Properties": {
                "Family": family,
                "RequiresCompatibilities": ["FARGATE"],
                "NetworkMode": "awsvpc",
                "Cpu": "256",
                "Memory": "512",
                "ContainerDefinitions": [
                    {
                        "Name": "primary",
                        "Image": CONTAINER_IMAGE,
                        "Essential": True,
                        "HealthCheck": _HEALTH_CHECK,
                    },
                    {
                        "Name": "secondary",
                        "Image": CONTAINER_IMAGE,
                        "Essential": True,
                        "DependsOn": [
                            {"ContainerName": "primary", "Condition": dependency_condition}
                        ],
                    },
                ],
            }},
        },
        "Outputs": {
            "TaskDefinitionArn": {"Value": {"Fn::GetAtt": ["TaskDef", "TaskDefinitionArn"]}},
        },
    }
    if conditions:
        template["Conditions"] = conditions
    return template


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


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
    """A container's DependsOn Condition built with Fn::If naming a template Condition that is
    not declared in the Conditions section is rejected by CreateStack before any resource is
    touched; the identical shape naming a declared Condition resolves and registers.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdependency.md
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    bad_family = ctx.unique_name("sim2real-xsvc-ecstddepbad-")
    bad_name = ctx.unique_name("sim2real-xsvc-ecstddepbadstack-")
    bad_template = _template(
        bad_family, conditions=None,
        dependency_condition={"Fn::If": ["HEALTHY", "HEALTHY", "START"]},
    )
    expect_error(
        lambda: cfn.create_stack(
            StackName=bad_name, TemplateBody=json.dumps(bad_template),
            Tags=[{"Key": "sim2real", "Value": bad_name}],
        ),
        *_UNRESOLVED_CONDITION,
    )

    # Effect-absent: CreateStack was refused outright, so no revision, active or
    # deregistered, was ever minted for this family.
    for status in ("ACTIVE", "INACTIVE"):
        listed = ecs.list_task_definitions(familyPrefix=bad_family, status=status)["taskDefinitionArns"]
        assert listed == [], f"expected no {status} revisions for {bad_family!r}, found {listed!r}"
    stacks = cfn.list_stacks(StackStatusFilter=[
        "CREATE_IN_PROGRESS", "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE",
    ])["StackSummaries"]
    names = {s["StackName"] for s in stacks}
    assert bad_name not in names, f"expected no stack named {bad_name!r} to exist, but it does"

    # Positive control: the identical shape, naming a Condition this template declares,
    # resolves Fn::If and registers the task definition with that dependency condition.
    good_family = ctx.unique_name("sim2real-xsvc-ecstddepgood-")
    good_name = ctx.unique_name("sim2real-xsvc-ecstddepgoodstack-")
    good_template = _template(
        good_family,
        conditions={"UseHealthy": {"Fn::Equals": ["enabled", "enabled"]}},
        dependency_condition={"Fn::If": ["UseHealthy", "HEALTHY", "START"]},
    )
    good_stack_id = cfn.create_stack(
        StackName=good_name, TemplateBody=json.dumps(good_template),
        Tags=[{"Key": "sim2real", "Value": good_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, good_stack_id))

    good_stack = _wait_create(cfn, good_stack_id)
    assert good_stack["StackStatus"] == "CREATE_COMPLETE", (
        f"the same shape naming a declared Condition ended {good_stack['StackStatus']!r} "
        f"({good_stack.get('StackStatusReason')!r}), expected 'CREATE_COMPLETE'"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in good_stack.get("Outputs", [])}
    control_arn = outputs["TaskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, control_arn))
    control = ecs.describe_task_definition(taskDefinition=control_arn)["taskDefinition"]
    by_name = {c["name"]: c for c in control["containerDefinitions"]}
    depends_on = by_name["secondary"]["dependsOn"]
    assert depends_on == [{"containerName": "primary", "condition": "HEALTHY"}], (
        f"control container dependency resolved to {depends_on!r}, expected Condition HEALTHY"
    )

    _delete_stack_and_wait(cfn, good_stack_id)
    after = ecs.describe_task_definition(taskDefinition=control_arn)["taskDefinition"]
    assert after["status"] == "INACTIVE", (
        f"the control revision must be INACTIVE after its stack delete, got {after['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
