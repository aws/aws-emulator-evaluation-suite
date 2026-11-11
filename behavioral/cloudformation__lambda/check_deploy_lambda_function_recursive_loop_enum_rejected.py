"""deploy-lambda-function-recursive-loop-enum-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-function-recursive-loop-enum-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_LAMBDA_CODE = "def handler(event, context):\n    return {'ok': True}\n"

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _template(function_name: str, recursive_loop: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": _TRUST},
            },
            "Fn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": _LAMBDA_CODE},
                    "RecursiveLoop": recursive_loop,
                },
            },
        },
    })


def _validation_errors(cfn, stack_name: str) -> list[tuple]:
    """``(logical id, type, name, status, mode, reason, path)`` of each VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend((e.get("LogicalResourceId"), e.get("ResourceType"), e.get("ValidationName"),
                    e.get("ValidationStatus"), e.get("ValidationFailureMode"), e.get("ValidationStatusReason"),
                    e.get("ValidationPath"))
                   for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR")
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """An AWS::Lambda::Function with RecursiveLoop outside {Allow, Terminate} fails CFN's
    property-value validation before any resource is provisioned; a listed value deploys and
    GetFunctionRecursionConfig reads back the same value through Lambda's own API."""
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    bad_stack = ctx.unique_name("sim2real-cfn-recloop-bad-")
    bad_fn = ctx.unique_name("sim2real-recloop-bad-")
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_fn, "Loop"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    status = _wait_terminal(cfn, bad_stack)
    assert status == "ROLLBACK_COMPLETE", f"expected the bad enum value to roll back, ended in {status!r}"

    events = [e for page in cfn.get_paginator("describe_stack_events").paginate(StackName=bad_stack)
              for e in page["StackEvents"]]
    stack_failed = [e.get("ResourceStatusReason") for e in events
                    if e["LogicalResourceId"] == bad_stack and e["ResourceStatus"] == "CREATE_FAILED"]
    assert stack_failed == [_STACK_REASON], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{_STACK_REASON!r}]"
    )
    found = _validation_errors(cfn, bad_stack)
    want = [(
        "Fn", "AWS::Lambda::Function", "PROPERTY_VALIDATION", "FAILED", "FAIL",
        "Loop is not a valid enum value. Supported values: [Allow, Terminate]",
        "/Resources/Fn/Properties/RecursiveLoop",
    )]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"

    code, message = _error(lambda: lam.get_function_recursion_config(FunctionName=bad_fn))
    assert (code, message) == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"the never-provisioned function's recursion config lookup answered {(code, message)!r}"
    )

    _delete_stack(cfn, bad_stack)
    code, message = _error(lambda: cfn.describe_stacks(StackName=bad_stack))
    assert (code, message) == ("ValidationError", f"Stack with id {bad_stack} does not exist"), (
        f"DescribeStacks of the deleted rolled-back stack answered {(code, message)!r}"
    )

    # Positive control: a listed enum value deploys, and Lambda reads back the same value.
    good_stack = ctx.unique_name("sim2real-cfn-recloop-good-")
    good_fn = ctx.unique_name("sim2real-recloop-good-")
    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(good_fn, "Allow"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    status = _wait_terminal(cfn, good_stack)
    assert status == "CREATE_COMPLETE", f"the control stack settled at {status!r}, expected CREATE_COMPLETE"

    conf = lam.get_function_recursion_config(FunctionName=good_fn)
    assert conf["RecursiveLoop"] == "Allow", (
        f"expected the deployed function's RecursiveLoop to read back as 'Allow', got {conf!r}"
    )

    _delete_stack(cfn, good_stack)
    code, message = _error(lambda: lam.get_function_recursion_config(FunctionName=good_fn))
    assert (code, message) == ("ResourceNotFoundException", "The resource you requested does not exist."), (
        f"the deleted control function's recursion config lookup answered {(code, message)!r}"
    )


def _wait_terminal(cfn, stack_name: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks every 2s until the stack settles; return the terminal status."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last.endswith("_COMPLETE") or last.endswith("_FAILED"):
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} never settled within {timeout_s}s (last={last!r})")


def _delete_stack(cfn, stack_name: str, timeout_s: float = 300.0) -> None:
    """Delete the stack and wait for it to vanish; DELETE_FAILED or the deadline raises."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", ""):
                return
            raise
        if not stacks:
            return
        status = stacks[0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} not deleted within {timeout_s}s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
