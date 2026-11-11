"""cfn-lambda-detect-stack-resource-drift-unknown-logical-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-detect-stack-resource-drift-unknown-logical-id-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_WAITER_DELAY_S = 2
_WAITER_ATTEMPTS = 150

_HANDLER_SRC = "def handler(event, context):\n    return {'statusCode': 200}\n"


@tags("axis:rejection", "concern:deploy", "concern:negative-classes", "plane:control", "cap:c1")
def run(ctx) -> None:
    """DetectStackResourceDrift on a LogicalResourceId absent from the stack is rejected with
    ValidationError naming the resource, while the real Lambda function still detects cleanly.
    """
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-lambdadriftneg-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    created = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert created == "CREATE_COMPLETE", f"stack {stack_name!r}: expected CREATE_COMPLETE, got {created!r}"

    # Break exactly one thing: ask for drift of a resource this stack never declared.
    code, message = _error_code(
        lambda: cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="NoSuchFn")
    )
    want_message = f"Resource NoSuchFn does not exist in stack {stack_id}"
    assert (code, message) == ("ValidationError", want_message), (
        f"expected ValidationError {want_message!r}, got {(code, message)!r}"
    )

    # Positive control, same file: the resource that IS in the stack still detects.
    clean = cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId="Fn")
    clean_status = clean["StackResourceDrift"]["StackResourceDriftStatus"]
    assert clean_status == "IN_SYNC", f"expected IN_SYNC for Fn, got {clean_status!r}"

    physical = {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    }
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name,
        WaiterConfig={"Delay": _WAITER_DELAY_S, "MaxAttempts": _WAITER_ATTEMPTS},
    )
    fn_name, role_name = physical["Fn"], physical["Role"]
    got = _error_code(lambda: ctx.client("lambda").get_function(FunctionName=fn_name))
    want = (
        "ResourceNotFoundException",
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn_name}",
    )
    assert got == want, f"GetFunction on the stack's function after the stack delete: {got!r}"
    got = _error_code(lambda: ctx.client("iam").get_role(RoleName=role_name))
    assert got == ("NoSuchEntity", f"The role with name {role_name} cannot be found."), (
        f"GetRole on the stack's role after the stack delete: {got!r}"
    )


def _template() -> str:
    """One IAM role and one Lambda function — the resource the bogus LogicalResourceId is not."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        }
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                        "Code": {"ZipFile": _HANDLER_SRC},
                    },
                },
            },
        }
    )


def _error_code(fn) -> tuple[str, str]:
    """The (Error.Code, Error.Message) ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _delete_stack_and_wait(cfn, stack_name: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 25}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
