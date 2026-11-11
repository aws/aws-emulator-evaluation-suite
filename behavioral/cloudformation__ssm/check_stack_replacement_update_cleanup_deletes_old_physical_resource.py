"""stack-replacement-update-cleanup-deletes-old-physical-resource."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stack-replacement-update-cleanup-deletes-old-physical-resource"
GROUP = "stack-update"
SERVICES = ["cloudformation", "ssm"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """Changing a create-only Name replaces the parameter: the new one is created first with the
    replacement reason, and the cleanup phase deletes the old physical id from SSM.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-update-behaviors.html"""
    cfn, ssm = ctx.client("cloudformation"), ctx.client("ssm")
    name = ctx.unique_name("sim2real-cfn-repl-")
    old, new = ("/" + ctx.unique_name(f"sim2real-cfn-repl-{k}-") for k in ("old", "new"))
    stack_id = _create(ctx, cfn, name, _template(old))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    assert ssm.get_parameter(Name=old)["Parameter"]["Value"] == "kept", f"{old!r} after create"
    before = len(_events(cfn, stack_id))

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(new))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"update ended {_stack(cfn, stack_id)!r}"
    rows = _rows(_events(cfn, stack_id)[before:], "PhysicalResourceId")
    assert [r[:3] for r in rows] == [
        (name, "UPDATE_IN_PROGRESS", "User Initiated"),
        ("Param", "UPDATE_IN_PROGRESS",
         "Requested update requires the creation of a new physical resource; hence creating one."),
        ("Param", "UPDATE_IN_PROGRESS", "Resource creation Initiated"),
        ("Param", "UPDATE_COMPLETE", None),
        (name, "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", None),
        ("Param", "DELETE_IN_PROGRESS", None),
        ("Param", "DELETE_COMPLETE", None),
        (name, "UPDATE_COMPLETE", None),
    ], f"events of the replacing update: {rows!r}"
    physical = [(r[1], r[3]) for r in rows if r[0] == "Param" and r[1] in ("UPDATE_COMPLETE", "DELETE_COMPLETE")]
    assert physical == [("UPDATE_COMPLETE", new), ("DELETE_COMPLETE", old)], (
        f"the replacement must complete as {new!r} and clean up {old!r}: {physical!r}")

    resource = cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId="Param")["StackResourceDetail"]
    assert resource["PhysicalResourceId"] == new, f"Param physical id after the update: {resource['PhysicalResourceId']!r}"
    assert ssm.get_parameter(Name=new)["Parameter"]["Value"] == "kept", f"{new!r} after the update"
    gone = _error(lambda: ssm.get_parameter(Name=old))
    assert gone == ("ParameterNotFound", ""), f"the replaced parameter {old!r} must be deleted: {gone!r}"


def _template(param: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter",
                                "Properties": {"Name": param, "Type": "String", "Value": "kept"}}},
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
