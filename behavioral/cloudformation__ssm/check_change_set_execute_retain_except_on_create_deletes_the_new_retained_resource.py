"""change-set-execute-retain-except-on-create-deletes-the-new-retained-resource."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "change-set-execute-retain-except-on-create-deletes-the-new-retained-resource"
GROUP = "change_sets"
SERVICES = ["cloudformation", "ssm"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]


def _template(keep, new=None):
    resources = {"Keep": {"Type": "AWS::SSM::Parameter",
                          "Properties": {"Name": keep, "Type": "String", "Value": "keep"}}}
    if new:
        resources["New"] = {"Type": "AWS::SSM::Parameter", "DeletionPolicy": "Retain",
                            "Properties": {"Name": new, "Type": "String", "Value": "new"}}
        # Bad takes New's Name through Ref New, so it fails only after New exists.
        resources["Bad"] = {"Type": "AWS::SSM::Parameter",
                            "Properties": {"Name": {"Ref": "New"}, "Type": "String", "Value": "x"}}
    return json.dumps({"Resources": resources})


def _reason(events, logical_id, status):
    """The ResourceStatusReason of the one ``logical_id`` event in ``status``."""
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


def _failed_update(ctx, cf, ssm, label, **execute):
    keep = "/" + ctx.unique_name(f"sim2real-xsvc-csreoc-{label}-")
    new = "/" + ctx.unique_name(f"sim2real-xsvc-csreoc-{label}-new-")
    ctx.on_cleanup(lambda: _delete_param(ssm, new))
    ctx.on_cleanup(lambda: _delete_param(ssm, keep))
    stack_id = cf.create_stack(StackName=ctx.unique_name(f"sim2real-xsvc-csreoc-{label}-"),
                               TemplateBody=_template(keep), Tags=_TAGS)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, stack_id))
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"[{label}] setup: {stack['StackStatus']!r}"
    cs_id = cf.create_change_set(StackName=stack_id, ChangeSetType="UPDATE",
                                 TemplateBody=_template(keep, new),
                                 ChangeSetName=ctx.unique_name("sim2real-xsvc-csreoc-cs-"))["Id"]
    cs = _wait_change_set(cf, cs_id, timeout_s=_cap(ctx, 180.0))
    assert cs["Status"] == "CREATE_COMPLETE", f"[{label}] change set: {cs.get('StatusReason')!r}"
    cf.execute_change_set(ChangeSetName=cs_id, **execute)
    stack = _wait_stack(cf, stack_id, timeout_s=_cap(ctx, 300.0))
    assert stack["StackStatus"] == "UPDATE_ROLLBACK_COMPLETE", (
        f"[{label}] the failed update must roll back, got {stack['StackStatus']!r}")
    events = _events(cf, stack_id)
    pairs = [(e["LogicalResourceId"], e["ResourceStatus"]) for e in events]
    assert ("New", "CREATE_COMPLETE") in pairs, pairs
    assert ("Bad", "CREATE_FAILED") in pairs, pairs
    got = (_reason(events, "Bad", "CREATE_FAILED"),
           _reason(events, stack["StackName"], "UPDATE_ROLLBACK_IN_PROGRESS"))
    want = (f"{new} already exists in stack {stack_id}",
            "The following resource(s) failed to create: [Bad]. ")
    assert got == want, f"[{label}] failure reasons: expected {want!r}, got {got!r}"
    assert ssm.get_parameter(Name=keep)["Parameter"]["Value"] == "keep", f"[{label}] Keep changed"
    return pairs, new


@tags("axis:happy-path", "cap:c3", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """ExecuteChangeSet(RetainExceptOnCreate=True) makes a rolled-back update delete the Retain
    resource it had created; the same rollback without the flag retains it in SSM.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ExecuteChangeSet.html
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    pairs, new = _failed_update(ctx, cf, ssm, "flag", RetainExceptOnCreate=True)
    assert ("New", "DELETE_COMPLETE") in pairs, pairs
    assert _error(lambda: ssm.get_parameter(Name=new)) == ("ParameterNotFound", ""), (
        "RetainExceptOnCreate must delete the newly created Retain parameter")

    pairs, new = _failed_update(ctx, cf, ssm, "noflag")
    assert ("New", "DELETE_SKIPPED") in pairs, pairs
    value = ssm.get_parameter(Name=new)["Parameter"]["Value"]
    assert value == "new", f"without the flag DeletionPolicy Retain keeps it, SSM reads {value!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
