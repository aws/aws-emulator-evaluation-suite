"""deploy-function-cloudformation-invoke-behavior."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-function-cloudformation-invoke-behavior"
GROUP = "state-machine"
SERVICES = ["lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Lambda::Function reaches CREATE_COMPLETE and can
    actually be Invoked, returning the payload its handler computes -- not merely a
    green stack status."""
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    stack_name = ctx.unique_name("sim2real-behav-lambda-cfn-invoke-")

    handler_src = (
        "def handler(event, context):\n"
        "    n = event.get('n', 0)\n"
        "    return {'multiplied': n * 2, 'marker': 'cfn-deployed'}\n"
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
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
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 10,
                    "Code": {"ZipFile": handler_src},
                },
            },
        },
        "Outputs": {"FunctionName": {"Value": {"Ref": "Fn"}}},
    }

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, stack_name))

    stack = _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"})
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"stack ended in {stack['StackStatus']}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    function_name = outputs["FunctionName"]

    config = lam.get_function_configuration(FunctionName=function_name)
    assert config["State"] == "Active", f"function state was {config['State']!r}"

    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps({"n": 21}).encode(),
    )
    assert resp["StatusCode"] == 200
    assert "FunctionError" not in resp
    payload = json.loads(resp["Payload"].read())
    assert payload == {"multiplied": 42, "marker": "cfn-deployed"}, payload

    # Teardown is proven, not merely attempted: delete the stack now (the on_cleanup
    # registration above stays as an idempotent safety net for an earlier failure) and
    # confirm the function is actually gone afterwards, not just the stack status label.
    _delete_stack_and_wait(ctx, stack_name)
    missing_code, missing_msg = _client_error(lambda: lam.get_function(FunctionName=function_name))
    assert missing_code == "ResourceNotFoundException", (
        f"function should be gone after stack delete, got {missing_code!r}"
    )
    fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{function_name}"
    assert missing_msg == f"Function not found: {fn_arn}", f"not-found message: {missing_msg!r}"


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=300.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        if last["StackStatus"] in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status; last={last!r}")


def _delete_stack_and_wait(ctx, stack_name, timeout_s=300.0, interval_s=5.0):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError:
            return
        if not stacks:
            return
        last = stacks[0]["StackStatus"]
        if last == "DELETE_COMPLETE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
