"""stack-update-resource-types-excluding-added-type-rejected."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-update-resource-types-excluding-added-type-rejected"
GROUP = "stack-update"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateStack whose ResourceTypes omits a type the update adds is refused and the stack keeps
    its resources; the identical update with that type allowed completes.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html"""
    cfn = ctx.client("cloudformation")
    stack_id = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-urtypes-"), _template(None))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    body = _template("/" + ctx.unique_name("sim2real-cfn-urtypes-p-"))

    got = _error(lambda: cfn.update_stack(StackName=stack_id, TemplateBody=body,
                                          ResourceTypes=["AWS::CloudFormation::WaitConditionHandle"]))
    want = ("ValidationError",
            "Resource type AWS::SSM::Parameter is not allowed by parameter ResourceTypes "
            "[AWS::CloudFormation::WaitConditionHandle]")
    assert got == want, f"expected {want!r}, got {got!r}"
    assert _stack(cfn, stack_id)["StackStatus"] == "CREATE_COMPLETE", f"the refusal moved the stack: {_stack(cfn, stack_id)!r}"
    assert _resources(cfn, stack_id) == ["Handle"], f"the refused update added resources: {_resources(cfn, stack_id)!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=body,
                     ResourceTypes=["AWS::CloudFormation::WaitConditionHandle", "AWS::SSM::Parameter"])
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"the allowed update ended {_stack(cfn, stack_id)!r}"
    assert _resources(cfn, stack_id) == ["Handle", "Param"], f"after the allowed update: {_resources(cfn, stack_id)!r}"


def _template(param: str | None) -> str:
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if param:
        res["Param"] = {"Type": "AWS::SSM::Parameter", "Properties": {"Name": param, "Type": "String", "Value": "v"}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


def _resources(cfn, stack_id: str) -> list[str]:
    return sorted(r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"])


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


def _create(ctx, cfn, name: str, body: str, **kw) -> str:
    """CreateStack with its delete registered at once; returns the StackId."""
    stack_id = cfn.create_stack(StackName=name, TemplateBody=body, Tags=_TAGS, **kw)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    return stack_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
