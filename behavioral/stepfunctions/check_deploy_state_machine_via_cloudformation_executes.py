"""deploy-state-machine-via-cloudformation-executes."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-state-machine-via-cloudformation-executes"
GROUP = "deploy"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state machine deployed via AWS::StepFunctions::StateMachine CFN executes per its ASL."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sim2real-sfn-cfn-")
    definition = {
        "StartAt": "SayHello",
        "States": {
            "SayHello": {
                "Type": "Pass",
                "Result": {"result": "executed-via-cfn"},
                "End": True,
            }
        },
    }
    template = _cfn_template_simple(sm_name, definition)
    _stack_name, outputs = _deploy_cfn(ctx, template)
    sm_arn = outputs["StateMachineArn"]

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert desc["status"] == "SUCCEEDED", (
        f"expected execution SUCCEEDED for state machine deployed via CFN, got {desc['status']!r}"
    )
    output = json.loads(desc["output"])
    assert output == {"result": "executed-via-cfn"}, (
        f"expected execution output {{'result': 'executed-via-cfn'}}, got {output!r}"
    )


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
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return stack_name, outputs


def _delete_stack(ctx, stack_name: str) -> None:
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
