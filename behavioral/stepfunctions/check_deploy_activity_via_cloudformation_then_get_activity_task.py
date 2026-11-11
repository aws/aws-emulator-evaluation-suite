"""deploy-activity-via-cloudformation-then-get-activity-task."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-activity-via-cloudformation-then-get-activity-task"
GROUP = "deploy"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """An Activity provisioned via CFN is immediately usable: GetActivityTask yields a task token."""
    sfn = ctx.client("stepfunctions")
    activity_name = ctx.unique_name("sim2real-sfn-cfn-act-")
    sm_name = ctx.unique_name("sim2real-sfn-cfn-sm-")
    template = _cfn_template_activity(sm_name, activity_name)
    _stack_name, outputs = _deploy_cfn(ctx, template)
    activity_arn = outputs["ActivityArn"]
    sm_arn = outputs["StateMachineArn"]

    desc_act = sfn.describe_activity(activityArn=activity_arn)
    assert desc_act["name"] == activity_name, (
        f"expected describe_activity name {activity_name!r}, got {desc_act['name']!r}"
    )

    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"job": 1}))[
        "executionArn"
    ]

    task = sfn.get_activity_task(activityArn=activity_arn, workerName="cfn-worker")
    assert task["taskToken"], "GetActivityTask returned no task token after execution scheduled work"
    task_input = json.loads(task["input"])
    assert task_input == {"job": 1}, f"expected task input {{'job': 1}}, got {task_input!r}"

    sfn.send_task_success(taskToken=task["taskToken"], output=json.dumps({"done": True}))
    desc = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert desc["status"] == "SUCCEEDED", (
        f"expected execution status SUCCEEDED after send_task_success, got {desc['status']!r}"
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


def _cfn_template_activity(sm_name: str, activity_name: str) -> str:
    definition_sub = json.dumps(
        {
            "StartAt": "DoTask",
            "States": {
                "DoTask": {
                    "Type": "Task",
                    "Resource": "${MyActivity}",
                    "TimeoutSeconds": 120,
                    "End": True,
                }
            },
        }
    )
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
                "MyActivity": {
                    "Type": "AWS::StepFunctions::Activity",
                    "Properties": {"Name": activity_name},
                },
                "MyStateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "StateMachineName": sm_name,
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionString": {"Fn::Sub": definition_sub},
                    },
                },
            },
            "Outputs": {
                "StateMachineArn": {"Value": {"Ref": "MyStateMachine"}},
                "ActivityArn": {"Value": {"Ref": "MyActivity"}},
            },
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
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
