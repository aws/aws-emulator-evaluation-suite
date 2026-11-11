"""stack-create-stack-policy-body-denies-modify-until-overridden."""

from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "stack-create-stack-policy-body-denies-modify-until-overridden"
GROUP = "stack-policy"
SERVICES = ["cloudformation", "ssm"]

#: Deny modifying Protected, allow every other update.
_POLICY = {"Statement": [
    {"Effect": "Deny", "Action": "Update:Modify", "Principal": "*", "Resource": "LogicalResourceId/Protected"},
    {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
]}
_ALLOW_ALL = {"Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]}


@tags("axis:happy-path", "cap:c7", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A StackPolicyBody given to CreateStack is stored and enforced: modifying the protected
    parameter is denied with the exact policy reason until a during-update override, which does not persist.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/protect-stack-resources.html"""
    cfn, ssm = ctx.client("cloudformation"), ctx.client("ssm")
    name = ctx.unique_name("sim2real-cfn-cpol-")
    prot, free = ("/" + ctx.unique_name(f"sim2real-cfn-cpol-{k}-") for k in ("prot", "free"))
    stack_id = _create(ctx, cfn, name, _template(prot, free, "p1", "f1"), StackPolicyBody=json.dumps(_POLICY))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"
    stored = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert stored == _POLICY, f"GetStackPolicy after CreateStack: {stored!r}"

    # Control: the policy allows modifying the unprotected parameter.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(prot, free, "p1", "f2"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"unprotected update ended {_stack(cfn, stack_id)!r}"
    assert _values(ssm, prot, free) == ("p1", "f2"), f"after the unprotected update: {_values(ssm, prot, free)!r}"

    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(prot, free, "p2", "f2"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"protected update ended {_stack(cfn, stack_id)!r}"
    denied = _of(_rows(_events(cfn, stack_id)[before:]), "Protected")
    assert denied == [("UPDATE_FAILED", "Action denied by stack policy: Statement [#1] does not allow "
                                        "[Update:Modify] for resource [LogicalResourceId/Protected];"),
                       ("UPDATE_COMPLETE", "Resource skipped during UpdateRollback")], (
        f"events of the denied resource: {denied!r}")
    assert _values(ssm, prot, free) == ("p1", "f2"), f"the denied update changed SSM: {_values(ssm, prot, free)!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(prot, free, "p2", "f2"),
                     StackPolicyDuringUpdateBody=json.dumps(_ALLOW_ALL))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_COMPLETE", f"overridden update ended {_stack(cfn, stack_id)!r}"
    assert _values(ssm, prot, free) == ("p2", "f2"), f"after the overridden update: {_values(ssm, prot, free)!r}"
    stored = json.loads(cfn.get_stack_policy(StackName=stack_id)["StackPolicyBody"])
    assert stored == _POLICY, f"the during-update override must not replace the stored policy: {stored!r}"

    # The override must not still be in EFFECT: an update that carries no override is denied
    # again. The stored-document check above alone would pass a target that keeps the override
    # active while reporting the old document.
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(prot, free, "p3", "f2"))
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"post-override update ended {_stack(cfn, stack_id)!r}"
    denied = _of(_rows(_events(cfn, stack_id)[before:]), "Protected")
    assert denied == [("UPDATE_FAILED", "Action denied by stack policy: Statement [#1] does not allow "
                                        "[Update:Modify] for resource [LogicalResourceId/Protected];"),
                       ("UPDATE_COMPLETE", "Resource skipped during UpdateRollback")], (
        f"events of the denied resource after the override expired: {denied!r}")
    assert _values(ssm, prot, free) == ("p2", "f2"), f"after the second denied update: {_values(ssm, prot, free)!r}"


def _template(prot: str, free: str, pv: str, fv: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Protected": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": prot, "Type": "String", "Value": pv}},
            "Free": {"Type": "AWS::SSM::Parameter", "Properties": {"Name": free, "Type": "String", "Value": fv}},
        },
    })


def _values(ssm, *names: str) -> tuple:
    return tuple(ssm.get_parameter(Name=n)["Parameter"]["Value"] for n in names)


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
