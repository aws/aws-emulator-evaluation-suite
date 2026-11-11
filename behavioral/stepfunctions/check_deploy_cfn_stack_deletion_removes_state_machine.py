"""deploy-cfn-stack-deletion-removes-state-machine."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-deletion-removes-state-machine"
GROUP = "deploy"
SERVICES = ["stepfunctions"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting the CFN stack results in the underlying state machine becoming unresolvable."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sim2real-sfn-cfn-del-")
    definition = {
        "StartAt": "S",
        "States": {"S": {"Type": "Pass", "Result": {"ok": True}, "End": True}},
    }
    template = _cfn_template_simple(sm_name, definition)
    stack_name, outputs = _deploy_cfn(ctx, template)
    sm_arn = outputs["StateMachineArn"]

    # sanity: it exists before deletion
    status = sfn.describe_state_machine(stateMachineArn=sm_arn)["status"]
    assert status == "ACTIVE", f"expected ACTIVE before deletion, got {status!r}"

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    def _probe():
        try:
            sfn.describe_state_machine(stateMachineArn=sm_arn)
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")
        return None

    code, message = _poll_until(_probe, lambda r: r is not None, timeout_s=90.0, interval_s=3.0)
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code!r}"
    expected = f"State Machine Does Not Exist: '{sm_arn}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # gone must also mean unusable: a mutation against the dead id fails the same way,
    # not just the read
    start_code, start_message = _error(lambda: sfn.start_execution(stateMachineArn=sm_arn, input="{}"))
    assert start_code == "StateMachineDoesNotExist", (
        f"expected StartExecution on the deleted state machine to fail with "
        f"StateMachineDoesNotExist, got {start_code!r}"
    )
    assert start_message == expected, f"expected message {expected!r}, got {start_message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _cfn_template_simple(sm_name: str, definition: dict) -> str:
    return json.dumps(
        {
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
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
            "Outputs": {"StateMachineArn": {"Value": {"Ref": "MyStateMachine"}}},
        }
    )


def _deploy_cfn(ctx, template_body: str):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-sfn-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_safe(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack_safe(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
