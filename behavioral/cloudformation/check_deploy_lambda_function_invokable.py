"""deploy-lambda-function-invokable."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-function-invokable"
GROUP = "deploy"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda function deployed via CloudFormation is actually invokable and computes
    the expected result, not merely reported as CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-lambda-")

    template = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
  AddFn:
    Type: AWS::Lambda::Function
    Properties:
      Runtime: python3.12
      Handler: index.handler
      Timeout: 10
      Role: !GetAtt ExecRole.Arn
      Code:
        ZipFile: |
          def handler(event, context):
              return {"sum": event["a"] + event["b"]}
Outputs:
  FunctionName:
    Value: !Ref AddFn
"""

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    status = _wait_stack_terminal(ctx, stack_name, timeout_s=300)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE (got {status})"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    fn_resource = next(r for r in resources if r["LogicalResourceId"] == "AddFn")
    function_name = fn_resource["PhysicalResourceId"]

    payload = _invoke_with_retry(ctx, function_name, {"a": 4, "b": 9}, timeout_s=60)
    assert payload == {"sum": 13}, f"unexpected lambda computed result: {payload}"

    lam = ctx.client("lambda")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_deleted(ctx, stack_name, timeout_s=180)

    stack_got = _expect_error(lambda: cfn.describe_stacks(StackName=stack_name))
    stack_expected = ("ValidationError", f"Stack with id {stack_name} does not exist")
    assert stack_got == stack_expected, (
        f"describing the deleted stack: expected {stack_expected!r}, got {stack_got!r}"
    )

    account = ctx.client("sts").get_caller_identity()["Account"]
    fn_arn = f"arn:aws:lambda:{ctx.region}:{account}:function:{function_name}"
    invoke_got = _expect_error(
        lambda: lam.invoke(FunctionName=function_name, Payload=json.dumps({"a": 1, "b": 1}).encode("utf-8"))
    )
    invoke_expected = ("ResourceNotFoundException", f"Function not found: {fn_arn}:$LATEST")
    assert invoke_got == invoke_expected, (
        f"invoking the deleted function: expected {invoke_expected!r}, got {invoke_got!r}"
    )


def _expect_error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.
    Raises when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
}


def _wait_stack_terminal(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _wait_stack_deleted(ctx, stack_name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    """Poll until the stack is gone (ValidationError by name) or DELETE_COMPLETE, raising on
    DELETE_FAILED or on timeout rather than returning a stale status."""
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError":
                return
            raise
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} entered DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s (last status={last_status})")


def _invoke_with_retry(ctx, function_name: str, payload: dict, timeout_s: float = 60.0, interval_s: float = 3.0) -> dict:
    """Invoke the function, tolerating the brief window where the freshly-created
    execution role has not yet propagated for Lambda to assume."""
    lam = ctx.client("lambda")
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        resp = lam.invoke(FunctionName=function_name, Payload=json.dumps(payload).encode("utf-8"))
        body = json.loads(resp["Payload"].read())
        if resp.get("FunctionError"):
            last_error = body
            time.sleep(interval_s)
            continue
        return body
    raise AssertionError(f"lambda invoke kept failing within {timeout_s}s: {last_error}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
