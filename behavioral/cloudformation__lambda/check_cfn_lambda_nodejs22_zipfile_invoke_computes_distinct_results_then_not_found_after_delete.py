"""cfn-lambda-nodejs22-zipfile-invoke-computes-distinct-results-then-not-found-after-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-nodejs22-zipfile-invoke-computes-distinct-results-then-not-found-after-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "exports.handler = async (event) => ({ square: event.n * event.n });\n"


def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": name, "Runtime": "nodejs22.x", "Handler": "index.handler",
                "Timeout": 15, "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "Code": {"ZipFile": _SRC}}},
        },
        "Outputs": {"FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
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


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed nodejs22.x AWS::Lambda::Function with an inline ZipFile reads back
    Runtime, Handler and a Zip PackageType, actually computes its Invoke result from each
    input rather than returning a fixed value, and is gone from Lambda once its stack deletes.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfn-nodesq-fn-")
    stack = ctx.unique_name("sim2real-cfn-nodesq-stk-")

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
    assert conf["Runtime"] == "nodejs22.x", f"expected Runtime nodejs22.x, got {conf['Runtime']!r}"
    assert conf["Handler"] == "index.handler", f"expected Handler index.handler, got {conf['Handler']!r}"
    assert conf["PackageType"] == "Zip", f"expected PackageType Zip, got {conf['PackageType']!r}"

    # The handler squares its input: two different inputs must produce two different,
    # correctly computed outputs rather than a fixed reply or an echo of the source text.
    first = lam.invoke(FunctionName=name, Payload=json.dumps({"n": 3}).encode())
    assert first["StatusCode"] == 200, f"expected StatusCode 200, got {first['StatusCode']!r}"
    assert first.get("FunctionError") is None, (
        f"unexpected FunctionError on n=3: {first.get('FunctionError')!r}")
    first_payload = json.loads(first["Payload"].read())
    assert first_payload == {"square": 9}, f"expected {{'square': 9}} for n=3, got {first_payload!r}"

    second = lam.invoke(FunctionName=name, Payload=json.dumps({"n": 7}).encode())
    assert second["StatusCode"] == 200, f"expected StatusCode 200, got {second['StatusCode']!r}"
    assert second.get("FunctionError") is None, (
        f"unexpected FunctionError on n=7: {second.get('FunctionError')!r}")
    second_payload = json.loads(second["Payload"].read())
    assert second_payload == {"square": 49}, f"expected {{'square': 49}} for n=7, got {second_payload!r}"
    assert first_payload != second_payload, (
        "two different inputs must not produce the same computed result"
    )

    _delete_stack(cfn, stack)
    code, message = _error(lambda: lam.get_function(FunctionName=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    want = f"Function not found: {outputs['FnArn']}"
    assert message == want, f"unexpected message {message!r}, wanted {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
