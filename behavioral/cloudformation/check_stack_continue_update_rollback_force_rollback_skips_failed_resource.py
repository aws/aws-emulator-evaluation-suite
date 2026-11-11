"""stack-continue-update-rollback-force-rollback-skips-failed-resource."""

from __future__ import annotations

import json
import re
import time

from botocore.config import Config

from behavioral_harness import tags

CHECK = "stack-continue-update-rollback-force-rollback-skips-failed-resource"
GROUP = "stack-rollback"
SERVICES = ["cloudformation"]

_SKIPPED_RESOURCES_REASON = (
    "One or more resources were skipped during UpdateRollback. These resources were not rolled "
    "back and may have drifted from the template. Run drift detection (DetectStackDrift) to "
    "review their current state before your next update."
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """From UPDATE_ROLLBACK_FAILED a plain ContinueUpdateRollback fails again on the same resource,
    while ForceRollback=True skips it, marks it UPDATE_COMPLETE and reaches UPDATE_ROLLBACK_COMPLETE.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ContinueUpdateRollback.html"""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-force-")
    stack_id = _create(ctx, cfn, name, _template("v1", breaker=False), Capabilities=["CAPABILITY_IAM"])
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "CREATE_COMPLETE", f"create ended {_stack(cfn, stack_id)!r}"

    cfn.update_stack(StackName=stack_id, TemplateBody=_template("v2", breaker=True), Capabilities=["CAPABILITY_IAM"])
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_FAILED", f"the failing update ended {_stack(cfn, stack_id)!r}"
    assert _status_of(cfn, stack_id, "Custom") == "UPDATE_FAILED", f"Custom after the failed rollback: {_resources(cfn, stack_id)!r}"

    # Control: without the flag the rollback retries Custom, which refuses again.
    before = len(_events(cfn, stack_id))
    cfn.continue_update_rollback(StackName=stack_id)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_FAILED", f"plain continue ended {_stack(cfn, stack_id)!r}"
    retried = _of(_rows(_events(cfn, stack_id)[before:]), "Custom")
    assert [r[0] for r in retried] == ["UPDATE_IN_PROGRESS", "UPDATE_FAILED"], f"Custom on the plain retry: {retried!r}"
    _assert_refusal_reason(retried[-1][1])

    before = len(_events(cfn, stack_id))
    _force_client(ctx).continue_update_rollback(StackName=stack_id)
    assert _settle(cfn, stack_id, timeout_s=_cap(ctx, _DEADLINE_S)) == "UPDATE_ROLLBACK_COMPLETE", f"forced continue ended {_stack(cfn, stack_id)!r}"
    rows = _rows(_events(cfn, stack_id)[before:])
    assert _of(rows, "Custom") == [("UPDATE_COMPLETE", "Resource skipped during UpdateRollback")], (
        f"Custom must be skipped, not retried: {_of(rows, 'Custom')!r}")
    assert _of(rows, name)[0] == ("UPDATE_ROLLBACK_IN_PROGRESS", "User Initiated"), f"stack events: {_of(rows, name)!r}"
    assert _of(rows, name)[-1] == ("UPDATE_ROLLBACK_COMPLETE", _SKIPPED_RESOURCES_REASON), (
        f"stack events: {_of(rows, name)!r}")
    assert _resources(cfn, stack_id) == {"Custom": "UPDATE_COMPLETE", "Fn": "CREATE_COMPLETE", "Role": "CREATE_COMPLETE"}, (
        f"resources after the forced rollback: {_resources(cfn, stack_id)!r}")


def _assert_refusal_reason(reason: str) -> None:
    """The custom resource's own FAILED response, split around the request id AWS assigns."""
    m = re.fullmatch(r"Received response status \[FAILED\] from custom resource\. Message returned: "
                     r"refusing rollback to v1 \(RequestId: ([0-9a-f-]{36})\)", reason or "")
    assert m, f"the custom resource refusal reason: {reason!r}"


def _force_client(ctx):
    """A client whose ContinueUpdateRollback request carries ForceRollback=true in its body.

    ForceRollback is sent in the request body because the client model may lack the member.
    """
    cfn = ctx.client("cloudformation", config=Config(user_agent_extra="force-rollback"))

    def add_force(params, **_):
        params["body"]["ForceRollback"] = "true"

    cfn.meta.events.register("before-call.cloudformation.ContinueUpdateRollback", add_force)
    return cfn


def _resources(cfn, stack_id: str) -> dict:
    return {r["LogicalResourceId"]: r["ResourceStatus"]
            for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]}


def _status_of(cfn, stack_id: str, logical_id: str) -> str:
    return _resources(cfn, stack_id)[logical_id]


#: Refuses an Update back to Phase v1 from v2 (only a rollback sends one) and a Create asking to fail.
_HANDLER = """
import cfnresponse

def handler(event, context):
    props = event.get("ResourceProperties", {})
    old = event.get("OldResourceProperties", {})
    kind = event["RequestType"]
    status, reason = cfnresponse.SUCCESS, "ok"
    if kind == "Create" and props.get("Fail") == "yes":
        status, reason = cfnresponse.FAILED, "refusing create"
    if kind == "Update" and props.get("Phase") == "v1" and old.get("Phase") == "v2":
        status, reason = cfnresponse.FAILED, "refusing rollback to v1"
    physical = event.get("PhysicalResourceId") or event["LogicalResourceId"]
    cfnresponse.send(event, context, status, {}, physical, reason=reason)
"""


def _template(phase: str, *, breaker: bool) -> str:
    """A role without policies (so the function writes no logs), the handler, Custom at ``phase``,
    and with ``breaker`` a second custom resource, created after Custom, that fails."""
    res: dict = {
        "Role": {"Type": "AWS::IAM::Role", "Properties": {"AssumeRolePolicyDocument": {
            "Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"},
                                                    "Action": "sts:AssumeRole"}]}}},
        "Fn": {"Type": "AWS::Lambda::Function", "Properties": {
            "Runtime": "python3.13", "Handler": "index.handler", "Timeout": 30,
            "Role": {"Fn::GetAtt": ["Role", "Arn"]}, "Code": {"ZipFile": _HANDLER}}},
        "Custom": {"Type": "Custom::Phase", "Properties": {
            "ServiceToken": {"Fn::GetAtt": ["Fn", "Arn"]}, "ServiceTimeout": "60", "Phase": phase}},
    }
    if breaker:
        res["Breaker"] = {"Type": "Custom::Breaker", "DependsOn": "Custom", "Properties": {
            "ServiceToken": {"Fn::GetAtt": ["Fn", "Arn"]}, "ServiceTimeout": "60", "Fail": "yes"}}
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
