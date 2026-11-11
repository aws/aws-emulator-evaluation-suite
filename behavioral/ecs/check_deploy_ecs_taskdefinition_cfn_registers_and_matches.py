"""deploy-ecs-taskdefinition-cfn-registers-and-matches."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-ecs-taskdefinition-cfn-registers-and-matches"
GROUP = "deploy"
SERVICES = ["ecs"]

_SIM2REAL_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-ecs-cfntaskdef"},
]

_CFN_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  Family:
    Type: String
Resources:
  TaskDef:
    Type: AWS::ECS::TaskDefinition
    Properties:
      Family: !Ref Family
      NetworkMode: bridge
      ContainerDefinitions:
        - Name: web
          Image: public.ecr.aws/docker/library/nginx:1.25-alpine
          Cpu: 128
          Memory: 256
          Essential: true
          Environment:
            - Name: STAGE
              Value: sim2real-check
          PortMappings:
            - ContainerPort: 80
              Protocol: tcp
Outputs:
  TaskDefinitionArn:
    Value: !Ref TaskDef
"""


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-registered task definition's containerDefinitions match the template byte-for-byte."""

    family = ctx.unique_name("sim2real-ecs-cfntaskdef-")
    _stack_name, outputs = _deploy_cfn(
        ctx,
        _CFN_TEMPLATE,
        parameters=[{"ParameterKey": "Family", "ParameterValue": family}],
    )
    task_def_arn = outputs["TaskDefinitionArn"]

    ecs = ctx.client("ecs")
    resp = ecs.describe_task_definition(taskDefinition=task_def_arn)
    td = resp["taskDefinition"]
    assert td["taskDefinitionArn"] == task_def_arn, (
        f"expected taskDefinitionArn {task_def_arn!r}, got {td['taskDefinitionArn']!r}"
    )
    assert td["family"] == family, f"expected family {family!r}, got {td['family']!r}"
    assert td["networkMode"] == "bridge", f"expected networkMode 'bridge', got {td['networkMode']!r}"
    assert len(td["containerDefinitions"]) == 1, (
        f"expected 1 containerDefinition, got {len(td['containerDefinitions'])}"
    )

    container = td["containerDefinitions"][0]
    assert container["name"] == "web", f"expected container name 'web', got {container['name']!r}"
    assert container["image"] == "public.ecr.aws/docker/library/nginx:1.25-alpine", (
        f"expected image 'public.ecr.aws/docker/library/nginx:1.25-alpine', got {container['image']!r}"
    )
    assert container["cpu"] == 128, f"expected cpu 128, got {container['cpu']!r}"
    assert container["memory"] == 256, f"expected memory 256, got {container['memory']!r}"
    assert container["essential"] is True, f"expected essential True, got {container['essential']!r}"
    assert container["environment"] == [{"name": "STAGE", "value": "sim2real-check"}], (
        f"expected environment [{{'name': 'STAGE', 'value': 'sim2real-check'}}], "
        f"got {container['environment']!r}"
    )
    port_mapping = container["portMappings"][0]
    assert port_mapping["containerPort"] == 80, (
        f"expected containerPort 80, got {port_mapping['containerPort']!r}"
    )
    assert port_mapping["protocol"] == "tcp", f"expected protocol 'tcp', got {port_mapping['protocol']!r}"


# ===== helpers =====

def _deploy_cfn(ctx, template_body, parameters=None, capabilities=None):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-ecs-stack-")
    kwargs = {"StackName": stack_name, "TemplateBody": template_body, "Tags": _SIM2REAL_TAGS}
    if parameters:
        kwargs["Parameters"] = parameters
    if capabilities:
        kwargs["Capabilities"] = capabilities

    def _cleanup():
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StackNotFoundException":
                raise

    cfn.create_stack(**kwargs)
    _record_stack_id = _task_definition_teardown(ctx, stack_name)
    ctx.on_cleanup(_cleanup)
    ctx.on_cleanup(_record_stack_id)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}
    return stack_name, outputs


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
