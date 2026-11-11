"""stack-create-resource-types-excluding-template-type-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-create-resource-types-excluding-template-type-rejected"
GROUP = "stack-create"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack whose ResourceTypes omits a type the template declares is refused and no stack
    exists; the same template with ResourceTypes naming every type it uses is created.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-rtypes-")
    body = _template("/" + ctx.unique_name("sim2real-cfn-rtypes-p-"))

    allowed = ["AWS::CloudFormation::WaitConditionHandle"]
    excluded = "AWS::SSM::Parameter"
    ctx.on_cleanup(lambda: _delete_stack_named(cfn, name))
    got = _error(lambda: cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS,
                                          ResourceTypes=allowed))
    want = ("ValidationError",
            f"Resource type {excluded} is not allowed by parameter ResourceTypes [{', '.join(allowed)}]")
    assert got == want, f"expected {want!r}, got {got!r}"
    absent = _error(lambda: cfn.describe_stacks(StackName=name))
    assert absent == ("ValidationError", f"Stack with id {name} does not exist"), (
        f"the refused create must leave no stack: {absent!r}")

    stack_id = _create(ctx, cfn, name, body,
                       ResourceTypes=["AWS::CloudFormation::WaitConditionHandle", excluded])
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"the allowed create ended {_stack(cfn, stack_id)!r}"
    made = sorted(r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"])
    assert made == ["Handle", "Param"], f"the allowed create must make both resources: {made!r}"


def _template(param: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Param": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": param, "Type": "String", "Value": "v"}},
        },
    })


# ===== helpers =====

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

#: A stack transition here takes seconds to a few minutes; the bound only stops a hung poll.
_DEADLINE_S = 600.0


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _poll(probe, done, *, timeout_s: float = _DEADLINE_S, interval_s: float = 3.0, what: str = "condition"):
    """Call ``probe()`` until ``done(result)`` holds and return the result; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} not reached within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(cfn, stack_id: str, timeout_s: float = _DEADLINE_S) -> str:
    """The stack's status once no operation is in progress on it."""
    return _poll(lambda: _stack(cfn, stack_id)["StackStatus"], lambda s: not s.endswith("_IN_PROGRESS"),
                 timeout_s=timeout_s, what=f"stack {stack_id} settled")


def _delete_stack(cfn, stack_id: str) -> None:
    """Delete the stack and wait for DELETE_COMPLETE by id; DELETE_FAILED or a timeout raises."""
    status = _stack(cfn, stack_id)["StackStatus"]
    if status == "UPDATE_IN_PROGRESS":
        cfn.cancel_update_stack(StackName=stack_id)
    if status != "CREATE_IN_PROGRESS":
        status = _settle(cfn, stack_id)
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(lambda: _stack(cfn, stack_id)["StackStatus"],
                  lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"), what=f"stack {stack_id} deleted")
    if final != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}")


def _delete_stack_named(cfn, name: str) -> None:
    """Delete the stack named ``name`` by its StackId if one exists; no such stack is a no-op."""
    try:
        stack_id = _stack(cfn, name)["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {name} does not exist":
            return
        raise
    _delete_stack(cfn, stack_id)


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
