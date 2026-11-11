"""stack-update-retain-except-on-create-deletes-new-retained-resource."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-update-retain-except-on-create-deletes-new-retained-resource"
GROUP = "stack-rollback"
SERVICES = ["cloudformation", "ssm"]


@tags("axis:happy-path", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A failed UpdateStack with RetainExceptOnCreate=True deletes the parameter it newly created
    despite DeletionPolicy Retain; the same failed update without the flag retains it.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_UpdateStack.html"""
    cfn, ssm = ctx.client("cloudformation"), ctx.client("ssm")
    name = ctx.unique_name("sim2real-cfn-urec-")
    with_flag, without = ("/" + ctx.unique_name(f"sim2real-cfn-urec-{k}-") for k in ("on", "off"))
    # Registered first so they run last: a rollback that retains a parameter leaves it behind.
    for param in (with_flag, without):
        ctx.on_cleanup(lambda param=param: _delete_parameter(ssm, param))
    stack_id = _create(ctx, cfn, name, _template(None))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(with_flag), RetainExceptOnCreate=True)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"flagged update ended {_stack(cfn, stack_id)!r}"
    kept_rows = [r[1] for r in _rows(_events(cfn, stack_id)[before:]) if r[0] == "Kept"]
    assert kept_rows == ["CREATE_IN_PROGRESS", "CREATE_IN_PROGRESS", "CREATE_COMPLETE",
                         "DELETE_IN_PROGRESS", "DELETE_COMPLETE"], f"Kept with the flag: {kept_rows!r}"
    gone = _error(lambda: ssm.get_parameter(Name=with_flag))
    assert gone == ("ParameterNotFound", ""), f"the newly created retained parameter must be deleted: {gone!r}"

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(without))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"control update ended {_stack(cfn, stack_id)!r}"
    kept_rows = [r[1] for r in _rows(_events(cfn, stack_id)[before:]) if r[0] == "Kept"]
    assert kept_rows == ["CREATE_IN_PROGRESS", "CREATE_IN_PROGRESS", "CREATE_COMPLETE", "DELETE_SKIPPED"], (
        f"Kept without the flag: {kept_rows!r}")
    assert ssm.get_parameter(Name=without)["Parameter"]["Value"] == "new", f"the retained parameter {without!r}"

    resources = [r["LogicalResourceId"] for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]]
    assert resources == ["Handle"], f"resources after both rollbacks: {resources!r}"


def _template(param: str | None) -> str:
    """A handle, and with ``param`` a retained parameter plus a wait condition that times out after it."""
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if param:
        res["Kept"] = {"Type": "AWS::SSM::Parameter", "DeletionPolicy": "Retain",
                       "Properties": {"Name": param, "Type": "String", "Value": "new"}}
        res["Fast"] = {"Type": "AWS::CloudFormation::WaitCondition", "DependsOn": "Kept",
                       "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


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


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _rows(events: list[dict], *keys: str) -> list[tuple]:
    """``(LogicalResourceId, ResourceStatus, ResourceStatusReason, *keys)`` per event; absent is None."""
    return [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"),
             *(e.get(k) for k in keys)) for e in events]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
