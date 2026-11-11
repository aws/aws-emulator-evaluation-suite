"""change-set-execute-client-request-token-marks-only-its-events."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "change-set-execute-client-request-token-marks-only-its-events"
GROUP = "change_sets"
SERVICES = ["cloudformation"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(*handles):
    return json.dumps({"Resources": {h: {"Type": "AWS::CloudFormation::WaitConditionHandle"}
                                     for h in handles}})


def _cap(ctx, own_s, margin_s=15.0):
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _wait_stack(cf, stack_id, *, timeout_s=300.0):
    """Poll DescribeStacks by id until the status leaves *_IN_PROGRESS; return the stack."""
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)


def _wait_change_set(cf, cs_id, *, timeout_s=180.0, **extra):
    """Poll DescribeChangeSet until CREATE_COMPLETE or FAILED; return the description."""
    deadline = time.monotonic() + timeout_s
    while True:
        cs = cf.describe_change_set(ChangeSetName=cs_id, **extra)
        if cs["Status"] in ("CREATE_COMPLETE", "FAILED"):
            return cs
        if time.monotonic() > deadline:
            raise AssertionError(f"change set still {cs['Status']!r} after {timeout_s}s")
        time.sleep(3)


def _delete_stack(cf, stack_id, *, timeout_s=600.0):
    """Delete a stack by id and poll until DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    cf.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if stack["StackStatus"] in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        if time.monotonic() > deadline:
            raise RuntimeError(f"stack {stack_id} still {stack['StackStatus']!r} after {timeout_s}s")
        time.sleep(3)
    if stack["StackStatus"] != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} ended {stack['StackStatus']!r}: "
                           f"{stack.get('StackStatusReason')!r}")


def _events(cf, stack_id):
    """Every StackEvent of the stack, oldest first."""
    out = []
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet's ClientRequestToken is stamped on every StackEvent of that execution and on
    no event of the stack's earlier create, which carries its own CreateStack token.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_StackEvent.html
    """
    cf = ctx.client("cloudformation")
    create_token = ctx.unique_name("sim2real-create-")
    exec_token = ctx.unique_name("sim2real-exec-")
    stack_id = cf.create_stack(StackName=ctx.unique_name("sim2real-behav-csexectok-"),
                               TemplateBody=_template("One"), Tags=_TAGS,
                               ClientRequestToken=create_token)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"setup stack: {stack['StackStatus']!r}"
    created_ids = {e["EventId"] for e in _events(cf, stack_id)}

    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 TemplateBody=_template("One", "Two"),
                                 ChangeSetName=ctx.unique_name("sim2real-behav-csexectok-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=cs_id, ClientRequestToken=exec_token)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_COMPLETE", f"execute: {stack['StackStatus']!r}"

    events = _events(cf, stack_id)
    old = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ClientRequestToken"))
           for e in events if e["EventId"] in created_ids]
    new = [(e["LogicalResourceId"], e["ResourceStatus"], e.get("ClientRequestToken"))
           for e in events if e["EventId"] not in created_ids]
    assert {t for _, _, t in old} == {create_token}, f"create events: {old!r}"
    assert {t for _, _, t in new} == {exec_token}, f"execution events: {new!r}"
    assert [(lid, st) for lid, st, _ in new] == [
        (stack["StackName"], "UPDATE_IN_PROGRESS"),
        ("Two", "CREATE_IN_PROGRESS"),
        ("Two", "CREATE_IN_PROGRESS"),
        ("Two", "CREATE_COMPLETE"),
        (stack["StackName"], "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS"),
        (stack["StackName"], "UPDATE_COMPLETE"),
    ], f"execution event sequence: {new!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
