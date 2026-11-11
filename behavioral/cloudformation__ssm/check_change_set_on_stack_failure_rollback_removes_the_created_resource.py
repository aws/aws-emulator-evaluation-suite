"""change-set-on-stack-failure-rollback-removes-the-created-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-on-stack-failure-rollback-removes-the-created-resource"
GROUP = "change_sets"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _colliding(name):
    return json.dumps({"Resources": {
        "A": {"Type": "AWS::SSM::Parameter",
              "Properties": {"Name": name, "Type": "String", "Value": "a"}},
        "B": {"Type": "AWS::SSM::Parameter",
              "Properties": {"Name": {"Ref": "A"}, "Type": "String", "Value": "b"}},
    }})


def _pairs(events):
    return [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]


def _reason(events, logical_id, status):
    found = [e.get("ResourceStatusReason") for e in events
             if (e["LogicalResourceId"], e["ResourceStatus"]) == (logical_id, status)]
    assert len(found) == 1, f"expected one {logical_id} {status} event, got {found!r}"
    return found[0]


def _error(fn):
    """(code, message) of the ClientError fn() raises; a success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a refusal, the call succeeded: {result!r}")


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


def _delete_param(ssm, name):
    """Delete an SSM parameter; only ParameterNotFound means it is already gone."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """OnStackFailure=ROLLBACK rolls a failed create back to ROLLBACK_COMPLETE with the exact rollback
    reason, records DisableRollback=False and deletes the parameter created before the failure.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stack-failure-options.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    name = "/" + ctx.unique_name("sim2real-xsvc-csosf-")
    ctx.on_cleanup(lambda: _delete_param(ssm, name))
    created = cf.create_change_set(
        StackName=ctx.unique_name("sim2real-xsvc-csosf-"), ChangeSetType="CREATE",
        ChangeSetName=ctx.unique_name("sim2real-xsvc-csosf-cs-"), TemplateBody=_colliding(name),
        OnStackFailure="ROLLBACK", Tags=_TAGS)
    stack_id = created["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    cs = _wait_change_set(cf, created["Id"], timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"change set: {cs.get('StatusReason')!r}"
    assert cs.get("OnStackFailure") == "ROLLBACK", cs.get("OnStackFailure")
    stack_name = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackName"]

    cf.execute_change_set(ChangeSetName=created["Id"])
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 400.0))
    assert stack["StackStatus"] == "ROLLBACK_COMPLETE", (
        f"OnStackFailure=ROLLBACK ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}")
    events = _events(cf, stack_id)
    pairs = _pairs(events)
    assert ("A", "CREATE_COMPLETE") in pairs, pairs
    assert ("B", "CREATE_FAILED") in pairs, pairs
    assert _reason(events, "B", "CREATE_FAILED") == f"{name} already exists in stack {stack_id}", (
        _reason(events, "B", "CREATE_FAILED"))

    assert _reason(events, stack_name, "ROLLBACK_IN_PROGRESS") == (
        "The following resource(s) failed to create: [B]. Rollback requested by user."), (
        _reason(events, stack_name, "ROLLBACK_IN_PROGRESS"))
    assert stack.get("DisableRollback") is False, stack.get("DisableRollback")
    assert ("A", "DELETE_COMPLETE") in pairs, pairs
    assert _error(lambda: ssm.get_parameter(Name=name)) == ("ParameterNotFound", ""), (
        "the rollback must delete the parameter A created")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
