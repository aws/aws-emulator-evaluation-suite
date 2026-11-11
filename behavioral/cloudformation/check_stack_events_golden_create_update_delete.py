"""stack-events-golden-create-update-delete."""

from __future__ import annotations

import json
import re
import time


from behavioral_harness import tags

CHECK = "stack-events-golden-create-update-delete"
GROUP = "stack-events"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create, update and delete each emit the exact ordered (logical id, status, reason) event list,
    with a dependency-ordered handle and parameter and a cleanup phase on the update.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_DescribeStackEvents.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-events-")
    param = "/" + ctx.unique_name("sim2real-cfn-events-p-")

    stack_id = _create(ctx, cfn, name, _template(param, "v1"))
    assert re.fullmatch(rf"arn:aws[a-z-]*:cloudformation:{ctx.region}:{ctx.account}:stack/{name}/[0-9a-f-]{{36}}",
                        stack_id), f"StackId {stack_id!r} is not a stack ARN for {name!r}"
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    created = _events(cfn, stack_id)

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(param, "v2"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"update ended {_stack(cfn, stack_id)!r}"
    updated = _events(cfn, stack_id)[len(created):]

    cfn.delete_stack(StackName=stack_id)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "DELETE_COMPLETE", f"delete ended {_stack(cfn, stack_id)!r}"
    deleted = _events(cfn, stack_id)[len(created) + len(updated):]

    want_create = [
        (name, "CREATE_IN_PROGRESS", "User Initiated"),
        ("Handle", "CREATE_IN_PROGRESS", None),
        ("Handle", "CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("Handle", "CREATE_COMPLETE", None),
        ("Param", "CREATE_IN_PROGRESS", None),
        ("Param", "CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("Param", "CREATE_COMPLETE", None),
        (name, "CREATE_COMPLETE", None),
    ]
    want_update = [
        (name, "UPDATE_IN_PROGRESS", "User Initiated"),
        ("Param", "UPDATE_IN_PROGRESS", None),
        ("Param", "UPDATE_COMPLETE", None),
        (name, "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", None),
        (name, "UPDATE_COMPLETE", None),
    ]
    want_delete = [
        (name, "DELETE_IN_PROGRESS", "User Initiated"),
        ("Param", "DELETE_IN_PROGRESS", None),
        ("Param", "DELETE_COMPLETE", None),
        ("Handle", "DELETE_IN_PROGRESS", None),
        ("Handle", "DELETE_COMPLETE", None),
        (name, "DELETE_COMPLETE", None),
    ]
    for label, got, want in (("create", created, want_create), ("update", updated, want_update),
                             ("delete", deleted, want_delete)):
        assert _rows(got) == want, f"{label} events: expected {want!r}, got {_rows(got)!r}"

    every = created + updated + deleted
    stack_rows = [e for e in every if e["LogicalResourceId"] == name]
    assert {(e["PhysicalResourceId"], e["ResourceType"], e["StackId"]) for e in stack_rows} == {
        (stack_id, "AWS::CloudFormation::Stack", stack_id)}, (
        f"stack-level events must name the stack by its id: {[(e['PhysicalResourceId'], e['ResourceType']) for e in stack_rows]!r}")
    param_done = [e["PhysicalResourceId"] for e in every
                  if e["LogicalResourceId"] == "Param" and e["ResourceStatus"].endswith("_COMPLETE")]
    assert param_done == [param, param, param], f"the parameter's physical id must be its name: {param_done!r}"
    ids = [e["EventId"] for e in every]
    assert len(set(ids)) == len(ids), f"EventIds must be unique: {ids!r}"
    stamps = [e["Timestamp"] for e in every]
    assert stamps == sorted(stamps), f"events across create, update, delete must be oldest first: {stamps!r}"


def _template(param: str, value: str) -> str:
    """A handle and a parameter that depends on it, so create and delete are serial."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Param": {"Type": "AWS::SSM::Parameter", "DependsOn": "Handle",
                      "Properties": {"Name": param, "Type": "String", "Value": value}},
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
