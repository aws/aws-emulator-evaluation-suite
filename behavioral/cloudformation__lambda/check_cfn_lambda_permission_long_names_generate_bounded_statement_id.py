"""cfn-lambda-permission-long-names-generate-bounded-statement-id."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-permission-long-names-generate-bounded-statement-id"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "def handler(event, context):\n    return {'ok': True}\n"
_PRINCIPAL = "events.amazonaws.com"
_PAD = "boundarytest"
_SID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
# CDK-style construct path concatenation: long, alphanumeric-only, 100+ characters.
_LOGICAL_ID = (
    "NestedAppConstructLambdaFunctionInvokePermissionFromScheduledRule"
    "WithALongCDKStyleLogicalIdentifier12AB34CD5"
)


def _long_stack_name(ctx) -> str:
    name = ctx.unique_name("sim2real-cfreslng-")
    while len(name) < 92:
        name += _PAD
    return name


def _template(fn_name: str) -> str:
    return json.dumps(
        {
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
                        }
                    },
                },
                "Fn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": fn_name,
                        "Runtime": "python3.12",
                        "Handler": "index.handler",
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {"ZipFile": _SRC},
                    },
                },
                _LOGICAL_ID: {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "FunctionName": {"Ref": "Fn"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": _PRINCIPAL,
                        "SourceAccount": {"Ref": "AWS::AccountId"},
                    },
                },
            },
            "Outputs": {"FnArn": {"Value": {"Fn::GetAtt": ["Fn", "Arn"]}}},
        }
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(
    probe,
    predicate,
    *,
    timeout_s=_STACK_DEADLINE_S,
    interval_s=2.0,
    description="condition",
    ctx=None,
):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s}s. Last: {last!r}")
        time.sleep(interval_s)


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _stack_status(cfn, stack: str) -> str:
    """StackStatus of ``stack`` (a StackId or name); only the exact not-found reads as "GONE"."""
    try:
        return cfn.describe_stacks(StackName=stack)["Stacks"][0]["StackStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == (
            "ValidationError",
            f"Stack with id {stack} does not exist",
        ):
            return "GONE"
        raise


def _delete_stack(cfn, stack: str) -> None:
    """Delete ``stack`` by StackId from any terminal state; raise unless DELETE_COMPLETE."""
    status = _stack_status(cfn, stack)
    if status in ("GONE", "DELETE_COMPLETE"):
        return
    if status.endswith("_IN_PROGRESS") and status != "DELETE_IN_PROGRESS":
        _poll(
            lambda: _stack_status(cfn, stack),
            lambda s: not s.endswith("_IN_PROGRESS"),
            description=f"stack {stack} terminal before delete",
        )
    cfn.delete_stack(StackName=stack)
    final = _poll(
        lambda: _stack_status(cfn, stack),
        lambda s: s in ("GONE", "DELETE_COMPLETE", "DELETE_FAILED"),
        description=f"stack {stack} deleted",
    )
    if final not in ("GONE", "DELETE_COMPLETE"):
        raise AssertionError(f"stack {stack} did not reach DELETE_COMPLETE, ended {final!r}")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A 90+ character stack name with a 100+ character AWS::Lambda::Permission logical id still
    gets a physical id that is a GetPolicy Sid of at most 100 characters matching [A-Za-z0-9_-]+,
    on the stack's function and conditioned on the stack's account."""
    assert len(_LOGICAL_ID) >= 100 and _LOGICAL_ID.isalnum(), (
        f"fixture logical id is {len(_LOGICAL_ID)} chars / alnum={_LOGICAL_ID.isalnum()}"
    )
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cfreslng-fn-")
    stack = _long_stack_name(ctx)
    assert len(stack) >= 90, f"fixture stack name is {len(stack)} chars, expected >= 90"

    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(fn_name),
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _poll(
        lambda: _stack_status(cfn, stack_id),
        lambda s: not s.endswith("_IN_PROGRESS"),
        timeout_s=_budget_s(ctx, _STACK_DEADLINE_S),
        description=f"stack {stack} terminal",
        ctx=ctx,
    )
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack ended in {status!r}"

    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    statement_id = next(
        r["PhysicalResourceId"] for r in resources if r["LogicalResourceId"] == _LOGICAL_ID
    )
    fn_arn = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["Outputs"]
    }["FnArn"]
    assert len(statement_id) <= 100, (
        f"generated statement id is {len(statement_id)} chars, expected <= 100: {statement_id!r}"
    )
    assert _SID_PATTERN.match(statement_id), (
        f"generated statement id {statement_id!r} does not match [A-Za-z0-9_-]+"
    )

    policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    statements = {s["Sid"]: s for s in policy["Statement"]}
    assert statement_id in statements, (
        f"statement {statement_id!r} not found in GetPolicy's statements {sorted(statements)!r}"
    )
    stmt = statements[statement_id]
    assert stmt["Action"] == "lambda:InvokeFunction", f"unexpected Action {stmt['Action']!r}"
    assert stmt["Principal"] == {"Service": _PRINCIPAL}, (
        f"unexpected Principal {stmt['Principal']!r}"
    )
    assert stmt["Effect"] == "Allow", f"unexpected Effect {stmt['Effect']!r}"
    assert stmt["Resource"] == fn_arn, (
        f"unexpected Resource {stmt['Resource']!r}, wanted {fn_arn!r}"
    )
    want_condition = {"StringEquals": {"AWS:SourceAccount": ctx.account}}
    assert stmt.get("Condition") == want_condition, (
        f"unexpected Condition {stmt.get('Condition')!r}, wanted {want_condition!r}"
    )

    _delete_stack(cfn, stack_id)
    want = "The resource you requested does not exist."
    code, message = _error(lambda: lam.get_policy(FunctionName=fn_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {code}: {message!r}"
    )
    assert message == want, f"unexpected message {message!r}, wanted {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
