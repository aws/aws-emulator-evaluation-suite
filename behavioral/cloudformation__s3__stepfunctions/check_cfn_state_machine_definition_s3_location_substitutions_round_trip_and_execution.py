"""cfn-state-machine-definition-s3-location-substitutions-round-trip-and-execution."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-state-machine-definition-s3-location-substitutions-round-trip-and-execution"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3", "stepfunctions"]

_RAW_DEFINITION = {
    "Comment": "uses a CloudFormation DefinitionSubstitutions placeholder",
    "StartAt": "Emit",
    "States": {
        "Emit": {
            "Type": "Pass",
            "Result": "${Greeting}",
            "End": True,
        }
    },
}


def _substituted_definition(value: str) -> dict:
    return {
        "Comment": "uses a CloudFormation DefinitionSubstitutions placeholder",
        "StartAt": "Emit",
        "States": {
            "Emit": {
                "Type": "Pass",
                "Result": value,
                "End": True,
            }
        },
    }


def _poll_until(
    probe, predicate, *, timeout_s: float, interval_s: float = 2.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_stack_or_leak(cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CFN state machine with DefinitionS3Location deploys with the S3 object's definition,
    DefinitionSubstitutions applied, and a started execution's output follows the substituted
    value rather than the literal placeholder.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    sfn = ctx.client("stepfunctions")

    bucket = ctx.unique_name("sim2real-behav-sfns3-")
    key = "definitions/machine.asl.json"
    greeting = "hello-from-s3"

    create_args = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        create_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_args)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(_RAW_DEFINITION).encode("utf-8"))
    ctx.on_cleanup(
        _teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchBucket", "NoSuchKey")
    )

    stack_name = ctx.unique_name("sim2real-behav-sfns3-stack-")
    sm_name = ctx.unique_name("sim2real-behav-sfns3-sm-")
    role_name = ctx.unique_name("sim2real-behav-sfns3-role-")

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
                        "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "DefinitionS3Location": {"Bucket": bucket, "Key": key},
                        "DefinitionSubstitutions": {"Greeting": greeting},
                    },
                },
            },
            "Outputs": {
                "StateMachineArn": {"Value": {"Ref": "MyStateMachine"}},
            },
        }
    )
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_or_leak(cfn, stack_id))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_id, WaiterConfig={"Delay": 2, "MaxAttempts": 225}
    )
    status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {status!r}"

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0].get("Outputs", [])
    }
    sm_arn = outputs["StateMachineArn"]

    desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
    expected_definition = _substituted_definition(greeting)
    assert json.loads(desc["definition"]) == expected_definition, (
        f"DescribeStateMachine's definition is {json.loads(desc['definition'])!r}, "
        f"expected the S3 object with the substitution applied: {expected_definition!r}"
    )

    execution_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    terminal = _poll_until(
        lambda: sfn.describe_execution(executionArn=execution_arn),
        lambda d: d["status"] in ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"),
        timeout_s=60.0,
        description="execution terminal",
    )
    assert terminal["status"] == "SUCCEEDED", (
        f"execution of the substituted definition ended {terminal['status']!r}, expected SUCCEEDED"
    )
    assert json.loads(terminal["output"]) == greeting, (
        f"execution output is {json.loads(terminal['output'])!r}, expected the substituted "
        f"value {greeting!r} rather than the literal placeholder"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
