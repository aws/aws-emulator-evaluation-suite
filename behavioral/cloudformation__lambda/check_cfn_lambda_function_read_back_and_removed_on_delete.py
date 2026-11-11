"""cfn-lambda-function-read-back-and-removed-on-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-function-read-back-and-removed-on-delete"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "def handler(event, context):\n    return {'ok': True}\n"


def _template(tok: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]}}},
            "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
                "FunctionName": tok, "Runtime": "python3.12", "Handler": "index.handler",
                "Timeout": 20, "MemorySize": 192,
                "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]}, "Code": {"ZipFile": _SRC}}},
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


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployed AWS::Lambda::Function reads back through Lambda's own GetFunction with the
    template's properties and its Fn::GetAtt Arn, then is actually gone — not just unlisted —
    once the owning stack is deleted, with the stack's execution role gone through IAM.
    """
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-cfres-fn-")
    stack = ctx.unique_name("sim2real-cfres-fnstk-")

    cfn.create_stack(StackName=stack, TemplateBody=_template(name),
                      Capabilities=["CAPABILITY_IAM"], Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(ctx, cfn, stack))
    status = _poll(lambda: _stack_status(cfn, stack), lambda s: not s.endswith("_IN_PROGRESS"),
                   description=f"stack {stack} terminal")
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    outputs = {o["OutputKey"]: o["OutputValue"] for o in
               cfn.describe_stacks(StackName=stack)["Stacks"][0].get("Outputs", [])}

    conf = lam.get_function(FunctionName=name)["Configuration"]
    assert conf["FunctionArn"] == outputs["FnArn"], (
        f"GetAtt Arn {outputs['FnArn']!r} != GetFunction's FunctionArn {conf['FunctionArn']!r}")
    assert conf["Runtime"] == "python3.12", f"expected Runtime python3.12, got {conf['Runtime']!r}"
    assert conf["Handler"] == "index.handler", f"expected Handler index.handler, got {conf['Handler']!r}"
    assert conf["Timeout"] == 20, f"expected Timeout 20, got {conf['Timeout']!r}"
    assert conf["MemorySize"] == 192, f"expected MemorySize 192, got {conf['MemorySize']!r}"

    # Delete the stack in-band and confirm the function is gone through Lambda's own API,
    # not merely dropped from the stack's resource list.
    role_name = cfn.describe_stack_resource(
        StackName=stack, LogicalResourceId="ExecRole")["StackResourceDetail"]["PhysicalResourceId"]
    _delete_stack(ctx, cfn, stack)
    want = f"Function not found: {outputs['FnArn']}"
    code, message = _error(lambda: lam.get_function(FunctionName=name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}: {message!r}"
    assert message == want, f"unexpected message {message!r}, wanted {want!r}"

    # The stack's execution role is gone too, through IAM's own API.
    code, message = _error(lambda: ctx.client("iam").get_role(RoleName=role_name))
    want = f"The role with name {role_name} cannot be found."
    assert (code, message) == ("NoSuchEntity", want), (
        f"GetRole of the deleted stack's role answered {(code, message)!r}, expected ('NoSuchEntity', {want!r})")


def _delete_stack(ctx, cfn, stack: str) -> None:
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
