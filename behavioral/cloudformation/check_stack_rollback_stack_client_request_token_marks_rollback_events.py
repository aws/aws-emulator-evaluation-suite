"""stack-rollback-stack-client-request-token-marks-rollback-events."""

from __future__ import annotations

import json
import time
import uuid


from behavioral_harness import tags

CHECK = "stack-rollback-stack-client-request-token-marks-rollback-events"
GROUP = "stack-update"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """RollbackStack's ClientRequestToken marks exactly the events of the rollback it starts from
    UPDATE_FAILED, the failed update keeps its own token, and the added resource is removed.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RollbackStack.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-rbtok-")
    update_tok, rollback_tok = (f"{p}-{uuid.uuid4().hex[:12]}" for p in ("update", "rollback"))
    stack_id = _create(ctx, cfn, name, _template(fail=False))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    before = len(_events(cfn, stack_id))

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(fail=True), DisableRollback=True,
                     ClientRequestToken=update_tok)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_FAILED", f"the failing update ended {_stack(cfn, stack_id)!r}"
    middle = len(_events(cfn, stack_id))

    cfn.rollback_stack(StackName=stack_id, ClientRequestToken=rollback_tok)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"rollback ended {_stack(cfn, stack_id)!r}"
    events = _events(cfn, stack_id)

    failed = _rows(events[before:middle], "ClientRequestToken")
    assert failed == [
        (name, "UPDATE_IN_PROGRESS", "User Initiated", update_tok),
        ("Fast", "CREATE_IN_PROGRESS", None, update_tok),
        ("Fast", "CREATE_IN_PROGRESS", "Resource creation Initiated", update_tok),
        ("Fast", "CREATE_FAILED", "WaitCondition timed out. Received 0 conditions when expecting 1", update_tok),
        (name, "UPDATE_FAILED", "The following resource(s) failed to create: [Fast]. ", update_tok),
    ], f"events of the failed update: {failed!r}"
    rolled = _rows(events[middle:], "ClientRequestToken")
    assert rolled == [
        (name, "UPDATE_ROLLBACK_IN_PROGRESS", "User Initiated Rollback", rollback_tok),
        (name, "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", None, rollback_tok),
        ("Fast", "DELETE_IN_PROGRESS", None, rollback_tok),
        ("Fast", "DELETE_COMPLETE", None, rollback_tok),
        (name, "UPDATE_ROLLBACK_COMPLETE", None, rollback_tok),
    ], f"events of the rollback: {rolled!r}"
    kept = [(r["LogicalResourceId"], r["ResourceStatus"])
            for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]]
    assert kept == [("Handle", "CREATE_COMPLETE")], f"resources after the rollback: {kept!r}"


def _template(*, fail: bool) -> str:
    """A handle, and with ``fail`` a wait condition that times out after one second."""
    res: dict = {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}}
    if fail:
        res["Fast"] = {"Type": "AWS::CloudFormation::WaitCondition",
                       "Properties": {"Handle": {"Ref": "Handle"}, "Timeout": "1", "Count": 1}}
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
