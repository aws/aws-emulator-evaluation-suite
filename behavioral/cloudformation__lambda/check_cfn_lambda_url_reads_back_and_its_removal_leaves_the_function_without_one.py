"""cfn-lambda-url-reads-back-and-its-removal-leaves-the-function-without-one."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-url-reads-back-and-its-removal-leaves-the-function-without-one"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_DEADLINE_S = 300.0

_HANDLER_CODE = "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n"


def _error(fn):
    """Call fn(), which AWS must refuse; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


def _poll(probe, done, *, timeout_s: float, interval_s: float = 2.0, what: str = "condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _status(cfn, stack_id: str) -> str:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]


def _settle(cfn, stack_id: str) -> str:
    return _poll(lambda: _status(cfn, stack_id), lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} settled")


def _failures(cfn, stack_id: str) -> list:
    events: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in events
            if e["ResourceStatus"].endswith("_FAILED")]


def _teardown_stack(cfn, stack_id: str) -> None:
    status = _status(cfn, stack_id)
    if status.endswith("_IN_PROGRESS") and status != "REVIEW_IN_PROGRESS":
        _settle(cfn, stack_id)
    if _status(cfn, stack_id) == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _status(cfn, stack_id), lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
                  timeout_s=_DEADLINE_S, interval_s=2.0, what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} ended {final}: {_failures(cfn, stack_id)!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Lambda::Url (AuthType AWS_IAM) reads back through Lambda with its GetAtt
    values; a stack update that drops it leaves the function with no URL config, and the stack
    delete removes the function and its role.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    role = ctx.unique_name("sim2real-cfn-url-role-")
    fn = ctx.unique_name("sim2real-cfn-url-")
    stack = ctx.unique_name("sim2real-cfn-url-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn,
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": _HANDLER_CODE},
                    "Timeout": 10,
                },
            },
            "Url": {
                "Type": "AWS::Lambda::Url",
                "Properties": {
                    "TargetFunctionArn": {"Ref": "Function"},
                    "AuthType": "AWS_IAM",
                },
            },
        },
        "Outputs": {
            "FunctionArnOut": {"Value": {"Fn::GetAtt": ["Url", "FunctionArn"]}},
            "FunctionUrlOut": {"Value": {"Fn::GetAtt": ["Url", "FunctionUrl"]}},
        },
    }

    stack_id = cfn.create_stack(
        StackName=stack, TemplateBody=json.dumps(template), Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    status = _settle(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack} ended {status}: {_failures(cfn, stack_id)!r}"

    outputs = {o["OutputKey"]: o["OutputValue"]
               for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]}
    expected_function_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{fn}"
    assert outputs["FunctionArnOut"] == expected_function_arn, (
        f"GetAtt FunctionArn is {outputs['FunctionArnOut']!r}, expected {expected_function_arn!r}")

    read_back = lam.get_function_url_config(FunctionName=fn)
    assert read_back["FunctionArn"] == expected_function_arn, (
        f"GetFunctionUrlConfig FunctionArn is {read_back['FunctionArn']!r}")
    assert read_back["AuthType"] == "AWS_IAM", (
        f"AuthType read back as {read_back['AuthType']!r}, expected AWS_IAM")
    assert read_back["FunctionUrl"] == outputs["FunctionUrlOut"], (
        f"GetFunctionUrlConfig FunctionUrl {read_back['FunctionUrl']!r} does not match "
        f"GetAtt FunctionUrl {outputs['FunctionUrlOut']!r}")
    assert read_back["FunctionUrl"].startswith("https://"), (
        f"FunctionUrl {read_back['FunctionUrl']!r} is not an https URL")

    # Remove only the Url: the function stays, so the URL's own deletion is observed.
    without_url = json.loads(json.dumps(template))
    del without_url["Resources"]["Url"]
    del without_url["Outputs"]
    cfn.update_stack(StackName=stack_id, TemplateBody=json.dumps(without_url),
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    status = _settle(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"stack {stack} update ended {status}: {_failures(cfn, stack_id)!r}"
    kept = lam.get_function(FunctionName=fn)["Configuration"]["FunctionArn"]
    assert kept == expected_function_arn, f"the function after the update is {kept!r}"
    code, message = _error(lambda: lam.get_function_url_config(FunctionName=fn))
    assert (code, message) == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"GetFunctionUrlConfig on the function after its Url was removed: {(code, message)!r}")

    _teardown_stack(cfn, stack_id)
    code, message = _error(lambda: lam.get_function(FunctionName=fn))
    assert (code, message) == ("ResourceNotFoundException", f"Function not found: {expected_function_arn}"), (
        f"GetFunction after the stack delete: {(code, message)!r}")
    iam = ctx.client("iam")
    code, message = _error(lambda: iam.get_role(RoleName=role))
    assert (code, message) == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
        f"GetRole on the execution role after the stack delete: {(code, message)!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
