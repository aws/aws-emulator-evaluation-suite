"""update-state-machine-preserves-arn-and-bumps-revision."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "update-state-machine-preserves-arn-and-bumps-revision"
GROUP = 'stack_resource_update'
SERVICES = ['cloudformation', 'stepfunctions']


def _template(sm_name: str, definition: dict) -> str:
    return json.dumps({
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    }
                },
            },
            "MyStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "StateMachineName": sm_name,
                    "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "DefinitionString": json.dumps(definition),
                },
            },
        },
    })


def _stack_resource(cf, stack_name, logical_id):
    return cf.describe_stack_resource(
        StackName=stack_name, LogicalResourceId=logical_id
    )["StackResourceDetail"]


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_stack(cf, stack_name: str) -> None:
    cf.delete_stack(StackName=stack_name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A definition change to a CFN-managed state machine updates it in place: the physical id
    (the state machine ARN) is kept, the new definition is served, and its revisionId advances.
    """
    cf = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    stack_name = ctx.unique_name("sim2real-xsvc-cfnsfn-")
    sm_name = ctx.unique_name("sim2real-xsvc-sm-")

    def_v1 = {"StartAt": "Initial", "States": {"Initial": {"Type": "Pass", "End": True}}}
    def_v2 = {"StartAt": "Updated", "States": {"Updated": {"Type": "Pass", "End": True}}}

    cf.create_stack(
        StackName=stack_name,
        TemplateBody=_template(sm_name, def_v1),
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_name))
    cf.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    initial = _stack_resource(cf, stack_name, "MyStateMachine")
    sm_arn = initial["PhysicalResourceId"]
    assert initial["ResourceStatus"] == "CREATE_COMPLETE", (
        f"state machine resource ended in {initial['ResourceStatus']!r}, expected CREATE_COMPLETE"
    )

    before = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert json.loads(before["definition"]) == def_v1, (
        f"pre-update definition was {before['definition']!r}, expected {def_v1!r}"
    )
    before_rev = before.get("revisionId")

    cf.update_stack(
        StackName=stack_name,
        TemplateBody=_template(sm_name, def_v2),
        Capabilities=["CAPABILITY_IAM"],
    )
    cf.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    updated = _stack_resource(cf, stack_name, "MyStateMachine")
    assert updated["PhysicalResourceId"] == sm_arn, (
        f"update replaced the resource: physical id went from {sm_arn!r} to "
        f"{updated['PhysicalResourceId']!r}, expected an in-place update"
    )
    assert updated["ResourceStatus"] == "UPDATE_COMPLETE", (
        f"state machine resource ended in {updated['ResourceStatus']!r}, expected UPDATE_COMPLETE"
    )

    after = _poll_until(
        lambda: sfn.describe_state_machine(stateMachineArn=sm_arn),
        lambda r: json.loads(r["definition"]).get("StartAt") == "Updated",
        description="post-update definition visible on describe",
    )
    assert json.loads(after["definition"]) == def_v2, (
        f"post-update definition was {after['definition']!r}, expected {def_v2!r}"
    )
    after_rev = after.get("revisionId")
    assert after_rev, "expected a non-blank revisionId on describe after the CFN update"
    assert after_rev != before_rev, (
        f"revisionId did not advance across the CFN update: before={before_rev!r} after={after_rev!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
