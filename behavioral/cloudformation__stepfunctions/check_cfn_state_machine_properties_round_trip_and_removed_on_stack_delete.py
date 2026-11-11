"""cfn-state-machine-properties-round-trip-and-removed-on-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-properties-round-trip-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "stepfunctions"]

_DEFINITION = {"StartAt": "S", "States": {"S": {"Type": "Pass", "Result": {"ok": True}, "End": True}}}


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::StepFunctions::StateMachine describes with the template's name, role,
    type and definition, its Ref and Fn::GetAtt values match Step Functions' own answer, and the
    in-band stack delete removes the state machine and its role."""
    cfn, sfn = ctx.client("cloudformation"), ctx.client("stepfunctions")
    stack_name = ctx.unique_name("sim2real-behav-sfnstack-")
    sm_name = ctx.unique_name("sim2real-behav-sm-")
    role_name = ctx.unique_name("sim2real-behav-smrole-")

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                },
                "MyStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": sm_name,
                        "StateMachineType": "STANDARD",
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionString": json.dumps(_DEFINITION),
                    },
                },
            },
            "Outputs": {
                "RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}},
                "StateMachineRef": {"Value": {"Ref": "MyStateMachine"}},
                "StateMachineGetAttArn": {"Value": {"Fn::GetAtt": ["MyStateMachine", "Arn"]}},
                "StateMachineGetAttName": {"Value": {"Fn::GetAtt": ["MyStateMachine", "Name"]}},
            },
        }
    )
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )
    outputs = _outputs(cfn, stack_name)
    role_arn = outputs["RoleArn"]
    ref_arn = outputs["StateMachineRef"]
    getatt_arn = outputs["StateMachineGetAttArn"]
    getatt_name = outputs["StateMachineGetAttName"]

    assert ref_arn == getatt_arn, (
        f"Ref and Fn::GetAtt Arn disagree on the same resource: {ref_arn!r} vs {getatt_arn!r}"
    )

    desc = sfn.describe_state_machine(stateMachineArn=ref_arn)
    assert desc["stateMachineArn"] == ref_arn, (
        f"describe_state_machine's own arn {desc['stateMachineArn']!r} does not match the "
        f"stack's physical id {ref_arn!r}"
    )
    assert desc["name"] == sm_name, f"expected name {sm_name!r}, got {desc['name']!r}"
    assert desc["name"] == getatt_name, (
        f"Fn::GetAtt Name {getatt_name!r} does not match describe_state_machine's name {desc['name']!r}"
    )
    assert desc["roleArn"] == role_arn, f"expected roleArn {role_arn!r}, got {desc['roleArn']!r}"
    assert desc["type"] == "STANDARD", f"expected type STANDARD, got {desc['type']!r}"
    assert desc["status"] == "ACTIVE", f"expected status ACTIVE, got {desc['status']!r}"
    assert json.loads(desc["definition"]) == _DEFINITION, (
        f"expected definition {_DEFINITION!r}, got {json.loads(desc['definition'])!r}"
    )

    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )

    def _probe():
        try:
            sfn.describe_state_machine(stateMachineArn=ref_arn)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        return None

    code, message = _poll_until(_probe, lambda r: r is not None, timeout_s=120.0)
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    expected_message = f"State Machine Does Not Exist: '{ref_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    got = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's role after the delete: {got!r}"
    )


def _outputs(cfn, stack_name: str) -> dict:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
        return
    try:
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
