"""stack-create-timeout-in-minutes-rolls-back."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "stack-create-timeout-in-minutes-rolls-back"
GROUP = "stack-create"
SERVICES = ["cloudformation"]


# timing:real-time — workflow: 60 s https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html
@tags("axis:happy-path", "cap:c4", "concern:deploy", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """TimeoutInMinutes=1 cancels a create still waiting after one minute, rolls it back with the
    timeout as the reason and ends ROLLBACK_COMPLETE; a create inside the minute completes.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateStack.html"""
    cfn = ctx.client("cloudformation")

    control = _create(ctx, cfn, ctx.unique_name("sim2real-cfn-tmo-ok-"), _template(wait=False), TimeoutInMinutes=1)
    assert _settle(cfn, control, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"a fast create under the timeout: {_stack(cfn, control)!r}"
    assert _stack(cfn, control)["TimeoutInMinutes"] == 1, f"TimeoutInMinutes echo: {_stack(cfn, control)!r}"

    name = ctx.unique_name("sim2real-cfn-tmo-")
    stack_id = _create(ctx, cfn, name, _template(wait=True), TimeoutInMinutes=1)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "ROLLBACK_COMPLETE", f"timed-out create ended {_stack(cfn, stack_id)!r}"
    events = _events(cfn, stack_id)
    rows = _rows(events)

    assert _of(rows, name) == [
        ("CREATE_IN_PROGRESS", "User Initiated"),
        ("ROLLBACK_IN_PROGRESS", "Stack creation time exceeded the specified timeout. Rollback requested by user."),
        ("ROLLBACK_COMPLETE", None),
    ], f"stack-level events: {_of(rows, name)!r}"
    assert _of(rows, "Wait") == [
        ("CREATE_IN_PROGRESS", None),
        ("CREATE_IN_PROGRESS", "Resource creation Initiated"),
        ("CREATE_FAILED", "Resource creation cancelled"),
        ("DELETE_IN_PROGRESS", None),
        ("DELETE_COMPLETE", None),
    ], f"events of the unsignalled wait condition: {_of(rows, 'Wait')!r}"

    # The timeout is the subject: the rollback may not begin before the minute has passed.
    began = events[0]["Timestamp"]
    rolled = next(e["Timestamp"] for e in events
                  if e["LogicalResourceId"] == name and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS")
    assert (rolled - began).total_seconds() >= 60, f"rollback began {(rolled - began).total_seconds()}s after the create"


def _template(*, wait: bool) -> str:
    """A handle, and with ``wait`` a wait condition that nothing signals for ten minutes."""
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if wait:
        res["Wait"] = {"Type": "AWS::CloudFormation::WaitCondition",
                       "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "600", "Count": 1}}
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": res})


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
