"""stack-rollback-events-golden-failed-and-cancelled."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "stack-rollback-events-golden-failed-and-cancelled"
GROUP = "stack-events"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A create whose wait condition times out cancels its in-flight sibling, names both in the
    rollback reason, deletes both before their handle, and ends ROLLBACK_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stack-failure-options.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-rbev-")

    stack_id = _create(ctx, cfn, name, _TEMPLATE)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "ROLLBACK_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    rows = _rows(_events(cfn, stack_id))

    assert _of(rows, name) == [
        ("CREATE_IN_PROGRESS", "User Initiated"),
        ("ROLLBACK_IN_PROGRESS",
         "The following resource(s) failed to create: [Fast, Slow]. Rollback requested by user."),
        ("ROLLBACK_COMPLETE", None),
    ], f"stack-level events: {_of(rows, name)!r}"
    assert _of(rows, "Fast") == [
        ("CREATE_IN_PROGRESS", None),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("CREATE_FAILED", "WaitCondition timed out. Received 0 conditions when expecting 1"),
        ("DELETE_IN_PROGRESS", None),
        ("DELETE_COMPLETE", None),
    ], f"events of the timed-out wait condition: {_of(rows, 'Fast')!r}"
    assert _of(rows, "Slow") == [
        ("CREATE_IN_PROGRESS", None),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("CREATE_FAILED", "Resource creation cancelled"),
        ("DELETE_IN_PROGRESS", None),
        ("DELETE_COMPLETE", None),
    ], f"events of the cancelled sibling: {_of(rows, 'Slow')!r}"
    assert _of(rows, "Handle") == [
        ("CREATE_IN_PROGRESS", None),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("CREATE_COMPLETE", None),
        ("DELETE_IN_PROGRESS", None),
        ("DELETE_COMPLETE", None),
    ], f"events of the shared handle: {_of(rows, 'Handle')!r}"

    at = {(r[0], r[1]): i for i, r in enumerate(rows)}
    order = [("Handle", "CREATE_COMPLETE"), ("Fast", "CREATE_FAILED"), ("Slow", "CREATE_FAILED"),
             (name, "ROLLBACK_IN_PROGRESS"), ("Fast", "DELETE_COMPLETE"), ("Handle", "DELETE_IN_PROGRESS"),
             (name, "ROLLBACK_COMPLETE")]
    assert [at[k] for k in order] == sorted(at[k] for k in order), (
        f"failure, cancellation, rollback and dependency-ordered deletes are out of order: {rows!r}")
    assert at[("Slow", "DELETE_COMPLETE")] < at[("Handle", "DELETE_IN_PROGRESS")], (
        f"the handle must be deleted after the wait condition that references it: {rows!r}")

    final = _stack(cfn, stack_id)
    assert "StackStatusReason" not in final, f"ROLLBACK_COMPLETE carries a reason: {final.get('StackStatusReason')!r}"
    left = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    assert sorted((r["LogicalResourceId"], r["ResourceStatus"]) for r in left) == [
        ("Fast", "DELETE_COMPLETE"), ("Handle", "DELETE_COMPLETE"), ("Slow", "DELETE_COMPLETE")], (
        f"every resource must be rolled back: {left!r}")


#: Fast times out after one second; Slow would wait ten minutes and is cancelled by the failure.
_TEMPLATE = json.dumps({
    "AWSTemplateFormatVersion": "2010-09-09",
    "Resources": {
        "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
        "Fast": {"Type": "AWS::CloudFormation::WaitCondition",
                 "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1}},
        "Slow": {"Type": "AWS::CloudFormation::WaitCondition",
                 "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "600", "Count": 1}},
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


def _of(rows: list[tuple], logical_id: str) -> list[tuple]:
    """The rows of one logical resource, without the logical id."""
    return [r[1:] for r in rows if r[0] == logical_id]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
