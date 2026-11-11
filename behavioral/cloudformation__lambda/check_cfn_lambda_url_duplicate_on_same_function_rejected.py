"""cfn-lambda-url-duplicate-on-same-function-rejected."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-url-duplicate-on-same-function-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_DEADLINE_S = 300.0

_HANDLER_CODE = "def handler(event, context):\n    return {'statusCode': 200, 'body': 'ok'}\n"

# CloudFormation's resource-handler wrapping of the service error; the request id and token vary.
_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*) \(Service: (?P<service>[A-Za-z0-9]+), '
    r'Status Code: (?P<status>\d+), Request ID: [^)]*\)(?: \(SDK Attempt Count: \d+\))?" '
    r'\(RequestToken: [^,]*, HandlerErrorCode: (?P<handler>[A-Za-z]+)\)$'
)


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


def _events(cfn, stack_id: str) -> list:
    out: list = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out


def _failures(cfn, stack_id: str) -> list:
    return [(e["LogicalResourceId"], e.get("ResourceStatusReason")) for e in _events(cfn, stack_id)
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


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second AWS::Lambda::Url on a function that already has one fails with Lambda's conflict
    message and rolls the stack back, leaving no function or role; one Url on the same template deploys.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")

    good = {"role": ctx.unique_name("sim2real-cfn-urld-okrole-"),
            "fn": ctx.unique_name("sim2real-cfn-urld-ok-"),
            "stack": ctx.unique_name("sim2real-cfn-urld-ok-")}
    bad = {"role": ctx.unique_name("sim2real-cfn-urld-badrole-"),
           "fn": ctx.unique_name("sim2real-cfn-urld-bad-"),
           "stack": ctx.unique_name("sim2real-cfn-urld-bad-")}

    def _template(names: dict, second_url: bool) -> dict:
        resources = {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": names["role"],
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": names["fn"],
                    "Runtime": "python3.13",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": _HANDLER_CODE},
                    "Timeout": 10,
                },
            },
            "Url": {
                "Type": "AWS::Lambda::Url",
                "Properties": {"TargetFunctionArn": {"Ref": "Function"}, "AuthType": "AWS_IAM"},
            },
        }
        if second_url:
            resources["SecondUrl"] = {
                "Type": "AWS::Lambda::Url",
                "DependsOn": "Url",
                "Properties": {"TargetFunctionArn": {"Ref": "Function"}, "AuthType": "AWS_IAM"},
            }
        return {"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources}

    def _create(names: dict, second_url: bool) -> str:
        stack_id = cfn.create_stack(
            StackName=names["stack"], TemplateBody=json.dumps(_template(names, second_url)),
            Capabilities=["CAPABILITY_NAMED_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["StackId"]
        ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
        return stack_id

    # Positive control: one Url on the same template deploys and reads back through Lambda.
    good_id = _create(good, second_url=False)
    status = _settle(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status}: {_failures(cfn, good_id)!r}"
    good_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{good['fn']}"
    config = lam.get_function_url_config(FunctionName=good["fn"])
    assert (config["FunctionArn"], config["AuthType"]) == (good_arn, "AWS_IAM"), (
        f"the control's URL config is {config!r}")

    # The one thing broken: a second Url on the same function and qualifier.
    bad_id = _create(bad, second_url=True)
    status = _settle(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack with a duplicate Lambda::Url ended {status!r}: {_failures(cfn, bad_id)!r}")
    reasons = [e.get("ResourceStatusReason", "") for e in _events(cfn, bad_id)
               if e["LogicalResourceId"] == "SecondUrl" and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(reasons) == 1, f"expected one CREATE_FAILED event for SecondUrl, got {reasons!r}"
    match = _REASON.match(reasons[0])
    assert match is not None, f"SecondUrl's reason is not a resource-handler message: {reasons[0]!r}"
    bad_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad['fn']}"
    got = (match["message"], match["service"], match["status"])
    want = (
        f"Failed to create function url config for [functionArn = {bad_arn}]. "
        f"Error message:  FunctionUrlConfig exists for this Lambda function",
        "Lambda",
        "409",
    )
    assert got == want, f"SecondUrl's CREATE_FAILED reason: expected {want!r}, got {got!r}"

    # Effect absent: the rollback removed the bad stack's function and role.
    _assert_gone(lam, iam, bad["fn"], bad_arn, bad["role"])

    for stack_id in (bad_id, good_id):
        _teardown_stack(cfn, stack_id)
        status = _status(cfn, stack_id)
        assert status == "DELETE_COMPLETE", f"stack {stack_id} after the delete is {status!r}"
    _assert_gone(lam, iam, good["fn"], good_arn, good["role"])


def _assert_gone(lam, iam, fn: str, fn_arn: str, role: str) -> None:
    """The function and its role answer their exact not-found errors."""
    got = _error(lambda: lam.get_function(FunctionName=fn))
    assert got == ("ResourceNotFoundException", f"Function not found: {fn_arn}"), (
        f"GetFunction({fn!r}): {got!r}")
    got = _error(lambda: iam.get_role(RoleName=role))
    assert got == ("NoSuchEntity", f"The role with name {role} cannot be found."), (
        f"GetRole({role!r}): {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
