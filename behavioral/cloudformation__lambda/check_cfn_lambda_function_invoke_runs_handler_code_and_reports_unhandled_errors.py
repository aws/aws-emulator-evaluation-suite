"""cfn-lambda-function-invoke-runs-handler-code-and-reports-unhandled-errors."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-function-invoke-runs-handler-code-and-reports-unhandled-errors"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = (
    "def handler(event, context):\n"
    "    if event.get('boom'):\n"
    "        raise ValueError('sim2real boom')\n"
    "    return {'sum': event['a'] + event['b']}\n"
)


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": name, "Runtime": "python3.12", "Handler": "index.handler",
                "Timeout": 20, "MemorySize": 192,
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
        },
        "Outputs": {"FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
    })


def _poll(
    probe, predicate, *, timeout_s=_STACK_DEADLINE_S, interval_s=2.0, description="condition"
):
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed AWS::Lambda::Function runs its handler on Invoke: a correct payload
    returns the computed result, a raised exception reports FunctionError with its exact
    type and message, and Invoke fails once the stack deletes the function.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfninv-fn-")
    stack = ctx.unique_name("sim2real-cfninv-fnstk-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(name),
                      Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack))
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal")
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in
               cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}
    conf = lam.get_function(FunctionName=name)["Configuration"]
    assert conf["FunctionArn"] == outputs["FnArn"], (
        f"GetAtt Arn {outputs['FnArn']!r} != GetFunction's FunctionArn {conf['FunctionArn']!r}")

    # Positive control: the handler actually runs and computes from its own input.
    ok = lam.invoke(FunctionName=name, Payload=json.dumps({"a": 2, "b": 3}).encode())
    assert ok.get("FunctionError") is None, (
        f"unexpected FunctionError on a valid payload: {ok.get('FunctionError')!r}")
    ok_payload = json.loads(ok["Payload"].read())
    assert ok_payload == {"sum": 5}, (
        f"expected the handler's computed {{'sum': 5}}, got {ok_payload!r}"
    )

    # Negative: an exception the handler raises is reported as an unhandled invoke error,
    # never swallowed into a false success, with the exact type and message it raised.
    bad = lam.invoke(FunctionName=name, Payload=json.dumps({"boom": True}).encode())
    assert bad.get("FunctionError") == "Unhandled", (
        f"expected FunctionError 'Unhandled' for a raised exception, got {bad.get('FunctionError')!r}")
    bad_payload = json.loads(bad["Payload"].read())
    assert bad_payload.get("errorType") == "ValueError", (
        f"expected errorType 'ValueError', got {bad_payload.get('errorType')!r}")
    assert bad_payload.get("errorMessage") == "sim2real boom", (
        f"expected errorMessage 'sim2real boom', got {bad_payload.get('errorMessage')!r}")

    _delete_stack(cfn, stack)
    code, message = _error(lambda: lam.invoke(FunctionName=name, Payload=b"{}"))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code}: {message!r}"
    )
    want = f"Function not found: {outputs['FnArn']}:$LATEST"
    assert message == want, f"unexpected message {message!r}, wanted {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
