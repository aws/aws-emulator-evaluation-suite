"""deploy-cfn-update-state-machine-definition-changes-execution-behavior."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-cfn-update-state-machine-definition-changes-execution-behavior"
GROUP = "deploy"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Updating a CFN-deployed state machine's Definition changes behavior of subsequent executions."""
    sfn = ctx.client("stepfunctions")
    sm_name = ctx.unique_name("sim2real-sfn-cfn-upd-")
    def_v1 = {
        "StartAt": "S",
        "States": {"S": {"Type": "Pass", "Result": {"version": "v1"}, "End": True}},
    }
    def_v2 = {
        "StartAt": "S",
        "States": {"S": {"Type": "Pass", "Result": {"version": "v2"}, "End": True}},
    }
    template_v1 = _cfn_template_simple(sm_name, def_v1)
    stack_name, outputs = _deploy_cfn(ctx, template_v1)
    sm_arn = outputs["StateMachineArn"]

    exec1 = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    desc1 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec1),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    out1 = json.loads(desc1["output"])
    assert out1 == {"version": "v1"}, f"expected pre-update execution output {{'version': 'v1'}}, got {out1!r}"

    template_v2 = _cfn_template_simple(sm_name, def_v2)
    _update_cfn(ctx, stack_name, template_v2)

    exec2 = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    desc2 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec2),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
    )
    out2 = json.loads(desc2["output"])
    assert out2 == {"version": "v2"}, f"expected post-update execution output {{'version': 'v2'}}, got {out2!r}"


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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    resp = cfn.describe_stacks(StackName=stack_name)
    outputs = {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}
    return stack_name, outputs


def _update_cfn(ctx, stack_name: str, template_body: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
    )
    cfn.get_waiter("stack_update_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


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
