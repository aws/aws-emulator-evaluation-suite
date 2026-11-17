"""cfn-lambda-version-of-nonexistent-function-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-version-of-nonexistent-function-rejected"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "def handler(event, context):\n    return {'ok': True}\n"


def _bad_template(missing_fn_name: str) -> str:
    """A lone AWS::Lambda::Version naming a function this stack never creates."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Ver": {"Type": "AWS::Lambda::Version", "Properties": {"FunctionName": missing_fn_name}},
        },
    })


def _good_template(fn_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": fn_name, "Runtime": "python3.12", "Handler": "index.handler",
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
            "Ver": {"Type": "AWS::Lambda::Version", "Properties": {"FunctionName": {"Ref": "Fn"}}},
        },
    })


def _poll(probe, predicate, *, timeout_s=_STACK_DEADLINE_S, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _stack_status(cfn, name: str) -> str:
    try:
        return cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        if "does not exist" in str(exc):
            return "GONE"
        raise


def _delete_stack(cfn, stack: str) -> None:
    status = _stack_status(cfn, stack)
    if status == "GONE":
        return
    if status.endswith("_IN_PROGRESS"):
        _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
              description=f"stack {stack} terminal before delete")
    cfn.delete_stack(StackName=stack)
    final = _poll(lambda: _stack_status(cfn, stack), lambda s: s in ("GONE", "DELETE_FAILED"),
                  description=f"stack {stack} deleted")
    if final != "GONE":
        raise AssertionError(f"stack {stack} did not reach DELETE_COMPLETE, ended {final!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Creating an AWS::Lambda::Version that names a function the account never created rolls the
    stack back with the Lambda not-found message, while the same template with a real function
    the stack creates itself reaches CREATE_COMPLETE.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    missing_fn_name = ctx.unique_name("sim2real-cfnlamverabsent-")
    bad_stack = ctx.unique_name("sim2real-cfnlamverabsentstk-")

    cfn.create_stack(StackName=bad_stack, TemplateBody=_bad_template(missing_fn_name))
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))
    bad_status = _poll(lambda: _stack_status(cfn, bad_stack), lambda s: not s.endswith("_IN_PROGRESS"),
                        description=f"stack {bad_stack} terminal")
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a Version naming a function this stack never created must roll back, got {bad_status!r}"
    )
    events = cfn.describe_stack_events(StackName=bad_stack)["StackEvents"]
    ver_failures = [
        e for e in events
        if e["LogicalResourceId"] == "Ver" and e["ResourceStatus"] == "CREATE_FAILED"
    ]
    assert ver_failures, f"no CREATE_FAILED event for Ver: {[e['ResourceStatus'] for e in events]!r}"
    reason = ver_failures[0]["ResourceStatusReason"]
    # The reason is 'Resource handler returned message: "<msg> (Service: <svc>, Status Code: <n>,
    # Request ID: <uuid>) (SDK Attempt Count: <n>)" (RequestToken: <uuid>, HandlerErrorCode: <code>)'.
    # The uuids and the attempt count vary per run, so each stable part is compared exactly.
    handler_message, _, rest = reason.partition(" (Service: ")
    want_handler_message = (
        'Resource handler returned message: "Function not found: '
        f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_fn_name}"
    )
    assert handler_message == want_handler_message, (
        f"Ver CREATE_FAILED reason {reason!r}; expected the handler message {want_handler_message!r}"
    )
    service_and_status = rest.partition(", Request ID: ")[0]
    assert service_and_status == "Lambda, Status Code: 404", (
        f"Ver CREATE_FAILED reason {reason!r}; GetFunction rejects the missing function with HTTP 404"
    )
    handler_code = reason.rpartition(", HandlerErrorCode: ")[2]
    assert handler_code == "NotFound)", (
        f"Ver CREATE_FAILED reason {reason!r}; the Lambda resource handler classifies this NotFound"
    )

    # The function was never created, confirmed through Lambda's own API.
    code, message = _error(lambda: lam.get_function(FunctionName=missing_fn_name))
    want_message = f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{missing_fn_name}"
    assert (code, message) == ("ResourceNotFoundException", want_message), (
        f"GetFunction for the never-created function: {(code, message)!r}, expected "
        f"('ResourceNotFoundException', {want_message!r})"
    )

    # Positive control: the identical shape, naming a function the stack creates itself, succeeds.
    good_fn_name = ctx.unique_name("sim2real-cfnlamverok-")
    good_stack = ctx.unique_name("sim2real-cfnlamverokstk-")
    cfn.create_stack(StackName=good_stack, TemplateBody=_good_template(good_fn_name),
                      Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))
    good_status = _poll(lambda: _stack_status(cfn, good_stack), lambda s: not s.endswith("_IN_PROGRESS"),
                         description=f"stack {good_stack} terminal")
    assert good_status == "CREATE_COMPLETE", (
        f"the same shape naming a function the stack creates must succeed, got {good_status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
