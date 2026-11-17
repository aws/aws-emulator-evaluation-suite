"""cfn-lambda-permission-missing-function-create-failed."""

from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-lambda-permission-missing-function-create-failed"
GROUP = "resource-existence"
SERVICES = ["cloudformation", "lambda"]

_STACK_DEADLINE_S = 300
_SRC = "def handler(event, context):\n    return {'ok': True}\n"
_PRINCIPAL = "events.amazonaws.com"
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


def _handler_reason(reason, account, *names):
    """``(message, HandlerErrorCode)`` of a resource-handler reason, masking only Request ID, SDK
    Attempt Count, the account and the run's names; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    text = re.sub(r"Request ID: [^,;)]+", "Request ID: <id>", m["message"])
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text, m["code"]


def _template(fn_name: str, missing_fn: str) -> str:
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
                "GoodPerm": {
                    "Type": "AWS::Lambda::Permission",
                    "Properties": {
                        "FunctionName": {"Ref": "Fn"},
                        "Action": "lambda:InvokeFunction",
                        "Principal": _PRINCIPAL,
                    },
                },
                # BadPerm names a function the stack never creates: its AddPermission fails after
                # GoodPerm, which it depends on, has succeeded.
                "BadPerm": {
                    "Type": "AWS::Lambda::Permission",
                    "DependsOn": "GoodPerm",
                    "Properties": {
                        "FunctionName": missing_fn,
                        "Action": "lambda:InvokeFunction",
                        "Principal": _PRINCIPAL,
                    },
                },
            },
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


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::Lambda::Permission naming a function that does not exist fails CREATE with a
    NotFound handler error, while the AWS::Lambda::Permission it depends on stays CREATE_COMPLETE
    and is a GetPolicy statement on its function."""
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-cfresmissfn-fn-")
    missing_fn = ctx.unique_name("sim2real-cfresmissfn-nope-")
    stack = ctx.unique_name("sim2real-cfresmissfn-stk-")

    stack_id = cfn.create_stack(
        StackName=stack,
        TemplateBody=_template(fn_name, missing_fn),
        Capabilities=["CAPABILITY_IAM"],
        DisableRollback=True,
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
    assert status == "CREATE_FAILED", f"expected CREATE_FAILED, stack ended in {status!r}"

    resources = {
        r["LogicalResourceId"]: r
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
    }
    bad = resources["BadPerm"]
    assert bad["ResourceStatus"] == "CREATE_FAILED", (
        f"BadPerm resource status was {bad['ResourceStatus']!r}, expected CREATE_FAILED"
    )
    got = _handler_reason(bad.get("ResourceStatusReason"), ctx.account, missing_fn)
    want = (
        f"Function not found: arn:{lam.meta.partition}:lambda:{ctx.region}:<account>:"
        "function:<name> "
        "(Service: Lambda, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
        "NotFound",
    )
    assert got == want, f"BadPerm failure reason {got!r}, wanted {want!r}"

    good = resources["GoodPerm"]
    assert good["ResourceStatus"] == "CREATE_COMPLETE", (
        f"GoodPerm resource status was {good['ResourceStatus']!r}, expected CREATE_COMPLETE "
        "(it completes before BadPerm, which depends on it, is attempted)"
    )
    good_sid = good["PhysicalResourceId"]
    policy = json.loads(lam.get_policy(FunctionName=fn_name)["Policy"])
    statements = {s["Sid"]: s for s in policy["Statement"]}
    assert good_sid in statements, (
        f"GoodPerm's statement {good_sid!r} not in GetPolicy's statements {sorted(statements)!r}"
    )
    stmt = statements[good_sid]
    assert stmt["Action"] == "lambda:InvokeFunction", f"unexpected Action {stmt['Action']!r}"
    assert stmt["Principal"] == {"Service": _PRINCIPAL}, (
        f"unexpected Principal {stmt['Principal']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
